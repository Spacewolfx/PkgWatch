"""Family 2 — new dangerous capabilities, npm (SPEC §4.5).

A capability counts as *new* only when the added line introduces it and the whole old tree
did not already have it. Detection is regular-expression matching over ADDED lines: tree
diffing cannot see through an alias, a computed member, or a string built at runtime, and
tree-sitter AST diffing is deliberately left to M4. Each docstring names the blind spots so
nobody "fixes" one by accident.
"""

from __future__ import annotations

from pkgwatch.models import DiffContext, Finding, RuleFamily, Severity
from pkgwatch.rules import registry, scan

JS_CHILD_PROCESS_ADDED = "JS_CHILD_PROCESS_ADDED"
DYNAMIC_EVAL_ADDED = "DYNAMIC_EVAL_ADDED"
NET_ACCESS_ADDED = "NET_ACCESS_ADDED"
FS_WRITE_OUTSIDE_PACKAGE_ADDED = "FS_WRITE_OUTSIDE_PACKAGE_ADDED"
ENV_ENUMERATION_ADDED = "ENV_ENUMERATION_ADDED"

# Every module name below has to be closed by the very next quote, which is what keeps
# ``require("child_processivity")`` quiet and makes a hit report the module that is actually
# named. The optional ``node:`` group covers the modern spelling of the same require.
_REQUIRE_PREFIX = r"""require\s*\(\s*["\x27](?:node:)?"""
_REQUIRE_SUFFIX = r"""["\x27]\s*\)"""


def _require_of(module: str) -> str:
    """Source for ``require("<module>")``, in either quote style and either spelling."""
    return _REQUIRE_PREFIX + module + _REQUIRE_SUFFIX


_CHILD_PROCESS_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern("child_process_require", _require_of("child_process")),
)

# A call whose callee is exactly the dynamic-code primitive, plus the equivalent constructor.
# The lookbehind rejects a member access and any identifier ending in those four letters —
# ``evaluate``, ``retrieval`` — and ``\s*`` between the name and its parenthesis is what keeps
# a comment that merely names the primitive from firing.
_DYNAMIC_EVAL_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern("eval_call", r"""(?<![A-Za-z0-9_.$])eval\s*\("""),
    scan.pattern("function_constructor", r"""\bnew\s+Function\s*\("""),
)

_NET_MODULES: tuple[str, ...] = ("https", "http", "net", "tls", "dgram", "dns")

_NET_ACCESS_PATTERNS: tuple[scan.Pattern, ...] = tuple(
    scan.pattern(f"{module}_require", _require_of(module)) for module in _NET_MODULES
)

# The write entry points whose argument list may name an escaping path. Longest name first so
# a line reading as two of them reports the more specific call.
_FS_WRITE_CALLS: tuple[str, ...] = (
    "writeFileSync",
    "appendFileSync",
    "createWriteStream",
    "writeFile",
    "appendFile",
)

# A write call and, still inside its argument list — ``[^;\n]*`` stops at the next statement —
# a quoted segment opening with two dots: ``".."``, ``"../out.js"`` or the backslash spelling.
# A path assembled only from variables has nothing here to match, which is the known gap.
_FS_WRITE_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern(
        "write_escaping_package_dir",
        r"""\b(?:""" + "|".join(_FS_WRITE_CALLS) + r""")\s*\([^;\n]*["\x27]\.\.(?:/|\\|["\x27])""",
    ),
)

# Whole-environment reads, spelled out token by token with only whitespace allowed between.
# ``process.env.HOME`` names one key and is configuration, not collection.
_ENV_PATTERNS: tuple[scan.Pattern, ...] = (
    scan.pattern(
        "enumerate_process_env",
        r"""Object\s*\.\s*keys\s*\(\s*process\s*\.\s*env\s*\)""",
    ),
    scan.pattern(
        "serialize_process_env",
        r"""JSON\s*\.\s*stringify\s*\(\s*process\s*\.\s*env\s*\)""",
    ),
)


@registry.register(
    rule_id=JS_CHILD_PROCESS_ADDED,
    rule_version=1,
    severity="high",
    ecosystems=("npm",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="A new child-process import lets the package start other programs.",
    common_benign_causes="A CLI helper, test runner, or build tool that shells out.",
)
def js_child_process_added(ctx: DiffContext) -> list[Finding]:
    """Detects the first line in the new version that pulls in child_process.

    One pattern, ``child_process_require``: the module named directly in a require, with or
    without the ``node:`` prefix, in either quote style. Matches are per added line and sorted
    by path then line; SPEC §4.5 means a require that the previous release already had
    anywhere in the package — including in a file this release deletes — is not new.

    Ignores deliberately: a capability reached indirectly, which no single line can resolve
    (``require(mod[name])``, a module name concatenated at runtime, a vendored or renamed
    polyfill, an import bound to another identifier), a require whose call is split across
    lines, and every file that is not a ``.js``/``.jsx``/``.mjs``/``.cjs`` text view —
    tree-sitter AST diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=JS_CHILD_PROCESS_ADDED,
        rule_version=1,
        severity=Severity.HIGH,
        patterns=_CHILD_PROCESS_PATTERNS,
    )


@registry.register(
    rule_id=DYNAMIC_EVAL_ADDED,
    rule_version=1,
    severity="high",
    ecosystems=("npm",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="Code built from a string is not visible in the shipped text.",
    common_benign_causes="A template engine, config parser, or test helper.",
)
def dynamic_eval_added(ctx: DiffContext) -> list[Finding]:
    """Detects a newly added call that compiles a string as code.

    Two patterns: ``eval_call`` for a call whose callee is exactly the dynamic-code primitive,
    and ``function_constructor`` for the same power under ``new Function``. A comment or an
    identifier that merely ends in those four letters is not a call, and the old-tree rule
    keeps a package that has always done this from being reported for doing it again.

    Ignores deliberately: member and computed access such as ``obj.eval`` or a property pulled
    off a global object, which the leading lookbehind rejects because a line cannot prove what
    that object is; a string built earlier and executed elsewhere, since only this line is
    evidence; ``process.env`` reads; non-JavaScript files; and code that is generated at
    install time rather than shipped — tree-sitter AST diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=DYNAMIC_EVAL_ADDED,
        rule_version=1,
        severity=Severity.HIGH,
        patterns=_DYNAMIC_EVAL_PATTERNS,
    )


@registry.register(
    rule_id=NET_ACCESS_ADDED,
    rule_version=1,
    severity="medium",
    ecosystems=("npm",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="A new network module import lets the package open connections.",
    common_benign_causes="An HTTP client, telemetry wrapper, or update checker.",
)
def net_access_added(ctx: DiffContext) -> list[Finding]:
    """Detects a newly added require of a network-capable core module.

    One pattern per module in ``_NET_MODULES`` — https, http, net, tls, dgram, dns — each
    named ``<module>_require`` so the finding says which socket family appeared. The quote
    that must follow the module name is why ``require("https")`` reports ``https_require`` and
    never ``http_require``, and why a URL-shaped string such as ``url.parse("local:8080")``
    is not a capability on its own.

    Ignores deliberately: traffic that goes through a third-party library or a global such as
    ``fetch``, which this table does not claim to enumerate; a socket opened from a module name
    built at runtime or reached through a computed require; a module list spelled with
    backticks, which is not valid here; a capability the old tree already had; and
    non-JavaScript files — tree-sitter AST diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=NET_ACCESS_ADDED,
        rule_version=1,
        severity=Severity.MEDIUM,
        patterns=_NET_ACCESS_PATTERNS,
    )


@registry.register(
    rule_id=FS_WRITE_OUTSIDE_PACKAGE_ADDED,
    rule_version=1,
    severity="medium",
    ecosystems=("npm",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="A write path escaping the package can create files outside it.",
    common_benign_causes="A CLI writing user config or a build tool emitting output.",
)
def fs_write_outside_package_added(ctx: DiffContext) -> list[Finding]:
    """Detects a file write whose path escapes the package directory.

    One pattern, ``write_escaping_package_dir``: a call in ``_FS_WRITE_CALLS`` and, later in
    the same statement, a quoted path segment that opens with two dots. Writing inside the
    package is ordinary behaviour for a build tool; a ``..`` segment is what turns the same
    call into a drop outside the sandbox, e.g. a startup file next to the caller's directory.

    Ignores deliberately: reads and streams opened for writing elsewhere, writes whose escape
    is assembled from variables — an absolute path or a resolved ``path.join`` has no literal
    two dots on the line to match — a call split over lines so the path lands on another one,
    a write the old tree already performed, and non-JavaScript files — tree-sitter AST diffing
    is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=FS_WRITE_OUTSIDE_PACKAGE_ADDED,
        rule_version=1,
        severity=Severity.MEDIUM,
        patterns=_FS_WRITE_PATTERNS,
    )


@registry.register(
    rule_id=ENV_ENUMERATION_ADDED,
    rule_version=1,
    severity="low",
    ecosystems=("npm",),
    families=(RuleFamily.DANGEROUS_CAPABILITY,),
    why_it_matters="Reading the whole environment exposes configuration values.",
    common_benign_causes="A diagnostic dump, config loader, or environment snapshot.",
)
def env_enumeration_added(ctx: DiffContext) -> list[Finding]:
    """Detects a line that enumerates the whole environment instead of reading one key.

    Two patterns: ``enumerate_process_env`` for a key list and ``serialize_process_env`` for a
    JSON dump. Both spell out ``process.env`` as the receiver, with only whitespace between the
    tokens. Reading one documented variable is configuration; handing over every token present
    in the environment is credential collection, which is why this is low on its own and needs
    a second family to corroborate before it means much.

    Ignores deliberately: ``process.env.HOME`` and any other single-key read, an enumeration
    behind a helper or a computed member such as a destructured environment object, an
    environment copy taken by spreading a local object rather than the global one, the same
    enumeration in the old tree, and non-JavaScript files — tree-sitter AST diffing is M4.
    """
    return scan.capability_findings(
        ctx,
        rule_id=ENV_ENUMERATION_ADDED,
        rule_version=1,
        severity=Severity.LOW,
        patterns=_ENV_PATTERNS,
    )
