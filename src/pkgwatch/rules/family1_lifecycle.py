"""Family 1 — npm lifecycle scripts (SPEC §4.5).

These hooks run without a human typing anything: npm executes them on install. Detection
here is limited to the package's own root manifest and the registry's copy of ``scripts``;
transitive dependencies, ``prepare`` in a workspace, and anything a lockfile pins are out
of scope for M2.
"""

from __future__ import annotations

import re

from pkgwatch.models import DiffContext, Finding, RuleFamily, Severity
from pkgwatch.rules import registry
from pkgwatch.rules.scan import ROOT_MANIFEST, declared_scripts, finding, root_manifest_additions

NPM_INSTALL_SCRIPT_ADDED = "NPM_INSTALL_SCRIPT_ADDED"
NPM_SCRIPT_INJECTION_FROM_METADATA = "NPM_SCRIPT_INJECTION_FROM_METADATA"

INSTALL_SCRIPT_KEYS = ("preinstall", "postinstall", "install")

# A manifest line that *declares* a key: the quoted name plus its colon, e.g.
# ``    "postinstall": "echo installed",``. The left quote is what keeps ``install`` from
# firing on ``"postinstall"``, and the backslash guard keeps an escaped key inside a string
# value (a hostile ``description`` field) from reading as a script declaration.
_SCRIPT_KEY_RE = re.compile(r'(?<!\\)"(' + "|".join(INSTALL_SCRIPT_KEYS) + r')"\s*:')


def _scripts_value_start(content: str) -> int | None:
    """Index of the ``{`` opening the top-level ``scripts`` object, or None.

    A string-aware scan: only a ``scripts`` key directly in the root object counts, so a
    nested ``scripts`` table is not mistaken for the hook table. Braces inside strings do
    not change depth.
    """
    depth = 0
    in_string = False
    escaped = False
    string_start = -1
    key: str | None = None
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
                if depth == 1:
                    j = i + 1
                    while j < n and content[j] in " \t\r\n":
                        j += 1
                    if j < n and content[j] == ":":
                        key = content[string_start + 1 : i]
            i += 1
            continue
        if ch == '"':
            in_string = True
            string_start = i
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == ":" and depth == 1 and key is not None:
            j = i + 1
            while j < n and content[j] in " \t\r\n":
                j += 1
            if key == "scripts" and j < n and content[j] == "{":
                return j
            key = None
            i = j
            continue
        i += 1
    return None


def _scripts_span(content: str) -> tuple[int, int] | None:
    """1-based inclusive line range of the top-level ``scripts`` object, or None.

    Minified JSON keeps the whole object on one line, so the span is that single line; a
    pretty-printed table spans its opening-brace line through its closing-brace line. Lines
    are counted on ``\\n`` only, matching the differ's line numbers.
    """
    start = _scripts_value_start(content)
    if start is None:
        return None
    depth = 0
    in_string = False
    escaped = False
    line = content.count("\n", 0, start) + 1
    start_line = line
    i = start
    n = len(content)
    while i < n:
        ch = content[i]
        if ch == "\n":
            line += 1
        elif in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return (start_line, line)
        i += 1
    return None


@registry.register(
    rule_id=NPM_INSTALL_SCRIPT_ADDED,
    rule_version=2,
    severity="high",
    ecosystems=("npm",),
    families=(RuleFamily.LIFECYCLE_SCRIPTS,),
    why_it_matters=(
        "Install-time hooks run automatically when a consumer installs the package, "
        "so a new hook changes what installation does."
    ),
    common_benign_causes=(
        "A native-module build step, a generated asset, or an install message "
        "added during a normal release."
    ),
)
def npm_install_script_added(ctx: DiffContext) -> list[Finding]:
    """Detects an install-time lifecycle script that the previous version did not declare.

    Only ``preinstall``, ``postinstall`` and ``install`` count, only in
    ``package/package.json`` — the manifest npm runs hooks from — and only inside the
    top-level ``scripts`` object. Added lines decide it, so a script that existed before is
    not re-reported. Every hook key on an added line is matched (never the command), in line
    then left-to-right order, so a minified line declaring two hooks yields two findings.

    Ignores deliberately: ``prepare``/``prepublishOnly`` (they run for the author, not for
    the consumer), ``test``/``build`` and any other non-install script, a dependency named
    ``install``/``preinstall``/``postinstall`` (a package name, not a hook), a ``scripts``
    table nested inside another field, a nested ``package.json`` under a fixtures or
    ``node_modules`` directory (not this package's hook), a manifest that vanished from the
    new tree, and the *command text* — whether the script says ``echo`` or ``curl`` is
    family 2 and 3 work, and line matching cannot see what a required file does (tree-sitter
    AST diffing is M4).
    """
    view = ctx.files_new.get(ROOT_MANIFEST)
    if view is None or not view.is_text:
        return []
    span = _scripts_span(view.content)
    if span is None:
        return []
    low, high = span
    findings: list[Finding] = []
    for line, text in root_manifest_additions(ctx):
        if not low <= line <= high:
            continue
        for match in _SCRIPT_KEY_RE.finditer(text):
            findings.append(
                finding(
                    ctx,
                    rule_id=NPM_INSTALL_SCRIPT_ADDED,
                    rule_version=2,
                    severity=Severity.HIGH,
                    path=ROOT_MANIFEST,
                    evidence=text.strip(),
                    line_start=line,
                    line_end=line,
                    details={"script": match.group(1)},
                )
            )
    return findings


@registry.register(
    rule_id=NPM_SCRIPT_INJECTION_FROM_METADATA,
    rule_version=1,
    severity="high",
    ecosystems=("npm",),
    families=(RuleFamily.LIFECYCLE_SCRIPTS,),
    why_it_matters=(
        "The registry copy of scripts can change without a visible source diff, "
        "so comparing both versions catches metadata-only edits."
    ),
    common_benign_causes=(
        "A publisher fixing a broken command or renaming a build step in the registry metadata."
    ),
)
def npm_script_injection_from_metadata(ctx: DiffContext) -> list[Finding]:
    """Detects an install-time script the registry advertises that the last release did not.

    The registry copy of ``scripts`` is what npm can run before the tarball is even read, so
    a ``preinstall`` that appears in ``metadata_after`` and not in ``metadata_before`` — or
    there with a different command — is the classic publish-hook injection. Compares
    ``metadata_before`` against ``metadata_after`` and reports only keys that are new or whose
    command changed, as package-level findings in sorted key order.

    Ignores deliberately: releases with no registry metadata at all (a local diff cannot be
    blamed for what the registry says), scripts that are unchanged between the two metadata
    blobs, non-install scripts such as ``build`` or ``test``, and metadata whose ``scripts``
    value is not a string — a list, number or null is a hostile or malformed shape, not a
    finding, and must not crash the worker. What the tarball itself contains is not
    re-checked here, and a script that hands off to a file is invisible to this comparison
    (tree-sitter AST diffing is M4).
    """
    before = declared_scripts(ctx.metadata_before)
    after = declared_scripts(ctx.metadata_after)

    findings: list[Finding] = []
    for key in sorted(INSTALL_SCRIPT_KEYS):
        command = after.get(key)
        if command is None or before.get(key) == command:
            continue
        findings.append(
            finding(
                ctx,
                rule_id=NPM_SCRIPT_INJECTION_FROM_METADATA,
                rule_version=1,
                severity=Severity.HIGH,
                evidence=f"{key}: {command}",
                details={"script": key, "source": "registry_metadata"},
            )
        )
    return findings
