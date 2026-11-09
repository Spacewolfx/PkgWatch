"""Family 4 — declared dependencies, PyPI (SPEC §4.5.2).

Reads the ``Requires-Dist`` lines of the shipped ``PKG-INFO``/``METADATA`` document on
both sides. The registry document is never consulted: what a wheel declares is what
gets installed alongside it.
"""

from __future__ import annotations

from pkgwatch.diff.pypi_metadata import metadata_text, parse_metadata
from pkgwatch.models import DiffContext, Finding, RuleFamily, Severity
from pkgwatch.rules import registry, scan

PYPI_DEPENDENCY_ADDED = "PYPI_DEPENDENCY_ADDED"


def _dependencies(ctx: DiffContext, side: str) -> dict[str, str]:
    text = metadata_text(ctx, side)
    if text is None:
        return {}
    return parse_metadata(text).dependencies


@registry.register(
    rule_id=PYPI_DEPENDENCY_ADDED,
    rule_version=1,
    severity="low",
    ecosystems=("pypi",),
    families=(RuleFamily.METADATA,),
    why_it_matters="A newly declared dependency widens what gets installed alongside the package.",
    common_benign_causes="A routine feature, refactor, or build tool update.",
)
def pypi_dependency_added(ctx: DiffContext) -> list[Finding]:
    """Detects dependency names declared in the new tree's metadata but not the old one's.

    Reads the shipped ``PKG-INFO``/``METADATA`` on both sides and reports one
    package-level finding per newly added dependency name, in sorted name order. The
    registry document's own dependency claims are never read.

    Ignores deliberately: dependencies that were removed, version-specifier changes to
    an existing dependency, a metadata document missing on both sides (nothing
    declared, nothing to diff), an unparseable document, and the dependency names the
    old tree already declared. Like the npm metadata family, this rule is
    experimental-gated by the runner.
    """
    before = _dependencies(ctx, "old")
    after = _dependencies(ctx, "new")
    return [
        scan.finding(
            ctx,
            rule_id=PYPI_DEPENDENCY_ADDED,
            rule_version=1,
            severity=Severity.LOW,
            evidence=f"new dependency: {name}",
            details={"dependency": name, "source": "pkg_info"},
        )
        for name in sorted(set(after) - set(before))
    ]
