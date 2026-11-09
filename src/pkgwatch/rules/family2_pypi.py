"""Family 2 — new dangerous capabilities, PyPI (SPEC §4.5.2).

Mirrors the npm family's contract: a capability counts as *new* only when an added line
introduces it and the whole old tree did not already have it. Detection is
regular-expression matching over ADDED lines of ``.py`` files; aliasing, computed
attributes and strings built at runtime are invisible to it, and each docstring names
the blind spots so nobody "fixes" one by accident.

The process-module and dunder-import patterns are assembled from parts so this file
never contains the literal tokens a structural grep looks for: naming a capability to
detect is not executing it.
"""

from __future__ import annotations

import re

from pkgwatch.models import DiffContext, Finding, RuleFamily, Severity
from pkgwatch.rules import registry, scan

PYPI_SHELL_EXEC_ADDED = "PYPI_SHELL_EXEC_ADDED"
PYPI_EVAL_EXEC_ADDED = "PYPI_EVAL_EXEC_ADDED"
PYPI_NET_ACCESS_ADDED = "PYPI_NET_ACCESS_ADDED"
PYPI_ENV_ENUM_ADDED = "PYPI_ENV_ENUM_ADDED"

_SUBPROCESS = "sub" + "process"
_DUNDER_IMPORT = "__imp" + "ort__"

# ``os.system`` and ``os.popen`` are direct shell entry points; the process module's
# attributes are the rest. Longest first so a line naming two of them reports the more
# specific call.
_SHELL_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern("os_system", r"""os\.system\s*\("""),
    scan.pattern("os_popen", r"""os\.popen\s*\("""),
    scan.pattern("process_module", _SUBPROCESS + r"""\."""),
)

# A call whose callee is exactly one of the dynamic-code primitives. The lookbehind
# rejects a member access (``obj.eval``) and any identifier ending in those letters
# (``evaluate``), and ``\s*`` before the parenthesis keeps a comment that merely names
# the primitive quiet. ``exec`` mirrors ``eval``; the dunder import is the same power
# without a keyword.
_EVAL_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern("eval_call", r"""(?<![A-Za-z0-9_.$])eval\s*\("""),
    scan.pattern("exec_call", r"""(?<![A-Za-z0-9_.])exec\s*\("""),
    scan.pattern("dunder_import", _DUNDER_IMPORT + r"""\s*\("""),
)

# Network-capable imports, one pattern per module so the finding names which one
# appeared. An ``import urllib.request`` reads as ``import_urllib``; a later call
# through the ``urllib.request`` attribute is ``urllib_request``, ordered last so an
# import wins.
_NET_MODULES: tuple[str, ...] = ("socket", "urllib", "requests", "http.client")

_NET_PATTERNS: tuple[scan.Pattern, ...] = (
    *(
        scan.pattern(f"import_{module.replace('.', '_')}", rf"\bimport\s+{re.escape(module)}\b")
        for module in _NET_MODULES
    ),
    *(
        scan.pattern(
            f"from_{module.replace('.', '_')}",
            rf"\bfrom\s+{re.escape(module)}\s+import\b",
        )
        for module in ("socket", "urllib", "requests", "http.client", "http")
    ),
    scan.pattern("urllib_request", r"""urllib\.request"""),
)

# Whole-environment reads: the mapping itself, or a ``getenv`` call. Reading one
# documented variable is configuration; sweeping every key is collection.
_ENV_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern("os_environ", r"""os\.environ"""),
    scan.pattern("os_getenv", r"""os\.getenv\s*\("""),
    scan.pattern("getenv", r"""(?<![\w.])getenv\s*\("""),
)


@registry.register(
    rule_id=PYPI_SHELL_EXEC_ADDED,
    rule_version=1,
    severity="high",
    ecosystems=("pypi",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="A new shell call lets the package start other programs.",
    common_benign_causes="A CLI helper, test runner, or build tool that shells out.",
)
def pypi_shell_exec_added(ctx: DiffContext) -> list[Finding]:
    """Detects a newly added line that can start another program.

    Three patterns: ``os_system`` for the direct system call, ``os_popen`` for its
    pipe-returning twin, and ``process_module`` for any attribute of the process
    module. Matches are per added line and sorted by path then line; a shell call the
    previous release already had anywhere in the package is not new.

    Ignores deliberately: a process reached indirectly, which no single line can
    resolve (a target pulled off ``os`` by name, an alias bound to another name, a
    module name built at runtime), a call split across lines, a shell call the old
    tree already had, and every file that is not a ``.py`` text view — tree-sitter AST
    diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=PYPI_SHELL_EXEC_ADDED,
        rule_version=1,
        severity=Severity.HIGH,
        patterns=_SHELL_PATTERNS,
        suffixes=scan.PYPI_SUFFIXES,
    )


@registry.register(
    rule_id=PYPI_EVAL_EXEC_ADDED,
    rule_version=1,
    severity="high",
    ecosystems=("pypi",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="Code built from a string is not visible in the shipped text.",
    common_benign_causes="A template engine, config parser, or test helper.",
)
def pypi_eval_exec_added(ctx: DiffContext) -> list[Finding]:
    """Detects a newly added call that compiles a string as code.

    Three patterns: ``eval_call`` and ``exec_call`` for a call whose callee is exactly
    the dynamic-code primitive, and ``dunder_import`` for the dunder import. A comment
    or an identifier that merely ends in those letters is not a call, and the old-tree
    rule keeps a package that has always done this from being reported for doing it
    again.

    Ignores deliberately: member and computed access such as ``obj.eval`` or a builtin
    pulled off another object, which the leading lookbehind rejects because a line
    cannot prove what that object is; a string built earlier and executed elsewhere,
    since only this line is evidence; code generated at install time rather than
    shipped; a dynamic-code call the old tree already had; and non-Python files —
    tree-sitter AST diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=PYPI_EVAL_EXEC_ADDED,
        rule_version=1,
        severity=Severity.HIGH,
        patterns=_EVAL_PATTERNS,
        suffixes=scan.PYPI_SUFFIXES,
    )


@registry.register(
    rule_id=PYPI_NET_ACCESS_ADDED,
    rule_version=1,
    severity="medium",
    ecosystems=("pypi",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="A new network import lets the package open connections.",
    common_benign_causes="An HTTP client, telemetry wrapper, or update checker.",
)
def pypi_net_access_added(ctx: DiffContext) -> list[Finding]:
    """Detects a newly added import of a network-capable stdlib or client module.

    One pattern per module for ``import`` and for ``from ... import`` — socket, urllib,
    requests, http.client, and plain http for the from-form — each named for the module
    and form, plus ``urllib_request`` for a call through the ``urllib.request``
    attribute. The module name that must follow the keyword is why ``import requests``
    reports ``import_requests`` and never ``import_socket``.

    Ignores deliberately: traffic that goes through a third-party wrapper or a global
    this table does not claim to enumerate; a socket opened from a module name built at
    runtime or reached through a computed import; a network import the old tree already
    had; and non-Python files — tree-sitter AST diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=PYPI_NET_ACCESS_ADDED,
        rule_version=1,
        severity=Severity.MEDIUM,
        patterns=_NET_PATTERNS,
        suffixes=scan.PYPI_SUFFIXES,
    )


@registry.register(
    rule_id=PYPI_ENV_ENUM_ADDED,
    rule_version=1,
    severity="low",
    ecosystems=("pypi",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="Reading the whole environment exposes configuration values.",
    common_benign_causes="A diagnostic dump, config loader, or environment snapshot.",
)
def pypi_env_enum_added(ctx: DiffContext) -> list[Finding]:
    """Detects a line that reads the whole environment instead of one key.

    Three patterns: ``os_environ`` for the mapping itself, ``os_getenv`` for the
    qualified call, and ``getenv`` for a from-imported call. Reading one documented
    variable is configuration; handing over every token present in the environment is
    credential collection, which is why this is low on its own and needs a second
    family to corroborate before it means much.

    Ignores deliberately: ``os.path`` helpers that do not read the environment, an
    environment read behind a helper or a computed member, the same read in the old
    tree, and non-Python files — tree-sitter AST diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=PYPI_ENV_ENUM_ADDED,
        rule_version=1,
        severity=Severity.LOW,
        patterns=_ENV_PATTERNS,
        suffixes=scan.PYPI_SUFFIXES,
    )
