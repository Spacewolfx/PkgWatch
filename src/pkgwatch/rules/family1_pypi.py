"""Family 1 — PyPI install hooks (SPEC §4.5.2).

A new build-time hook changes what installation does: these files are read as text
only, never executed. Detection is added-line matching in the package's own build
manifests with an old-tree check, so a hook that merely rides along a version bump is
not re-reported.
"""

from __future__ import annotations

from pkgwatch.models import DiffContext, Finding, RuleFamily, Severity
from pkgwatch.rules import registry, scan

PYPI_INSTALL_HOOK_ADDED = "PYPI_INSTALL_HOOK_ADDED"

# Most specific first: ``setuptools.setup(`` is the qualified spelling of the same call,
# so a line reading as both reports the qualified name.
_HOOK_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern("setuptools_setup", r"""setuptools\.setup\s*\("""),
    scan.pattern("setup_call", r"""setup\s*\("""),
    scan.pattern("project_scripts", r"""^\s*\[project\.scripts\]"""),
    scan.pattern("project_entry_points", r"""^\s*\[project\.entry-points"""),
)


@registry.register(
    rule_id=PYPI_INSTALL_HOOK_ADDED,
    rule_version=1,
    severity="high",
    ecosystems=("pypi",),
    families=(RuleFamily.LIFECYCLE_SCRIPTS,),
    why_it_matters=(
        "Build-time hooks run automatically when a consumer installs the package, "
        "so a new hook changes what installation does."
    ),
    common_benign_causes=(
        "A new console script, a native-module build step, or a generated asset "
        "added during a normal release."
    ),
)
def pypi_install_hook_added(ctx: DiffContext) -> list[Finding]:
    """Detects an install hook that the previous version did not declare in its build files.

    Added lines of the new tree's own build manifests (``setup.py``, ``pyproject.toml``,
    ``setup.cfg`` at depth <= 2) matching a hook pattern: the ``setuptools``-qualified
    call, the bare ``setup`` call, a ``[project.scripts]`` table, or an
    ``[project.entry-points`` table. One finding per matching line, the first pattern
    that matches a line winning, in path then line order.

    Ignores deliberately: a hook the old tree's build files already declared — a
    version bump that rewrites the ``setup(`` line's text is not a new hook — a command
    or console script body the line points at, which line matching cannot resolve; a
    build file nested deeper than two directories, which is not this package's own
    declaration; and anything the build files do not literally declare, including a
    ``setup.cfg`` option that runs a command indirectly (line matching cannot see what
    an option's value does — tree-sitter AST diffing is M4).
    """
    hits: list[tuple[str, int, str, scan.Pattern]] = []
    for path, number, text in scan.build_file_additions(ctx):
        for item in _HOOK_PATTERNS:
            if item.regex.search(text):
                hits.append((path, number, text, item))
                break

    present = {item.name: scan.old_build_files_have(ctx, item) for item in _HOOK_PATTERNS}
    scan_state = scan.old_tree_state(ctx)
    findings: list[Finding] = []
    for path, number, text, item in sorted(hits, key=lambda hit: (hit[0], hit[1])):
        if present[item.name]:
            continue
        findings.append(
            scan.finding(
                ctx,
                rule_id=PYPI_INSTALL_HOOK_ADDED,
                rule_version=1,
                severity=Severity.HIGH,
                path=path,
                evidence=text.strip(),
                line_start=number,
                line_end=number,
                details={"pattern": item.name, "old_tree_scan": scan_state},
            )
        )
    return findings
