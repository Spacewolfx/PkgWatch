"""Family 4 — metadata changes, npm (SPEC §4.5.1).

v0.2 ships ``DEPENDENCY_ADDED`` (registry ``versions[v].dependencies``) and
``REPOSITORY_URL_CHANGED`` (``repository`` in the root ``package.json`` of both trees).
``MAINTAINER_ADDED`` is DEFERRED: package-level maintainers is a current-state snapshot,
not a per-version value, so it cannot be diffed. TODO in SPEC §3 / §4.5.1.

Operator decision 2026-11-07: initial untuned values, not measured.
"""

from __future__ import annotations

from typing import Any

from pkgwatch.diff.manifest import normalize_repository, read_root_manifest
from pkgwatch.models import DiffContext, Finding, RuleFamily, Severity
from pkgwatch.rules import registry, scan

DEPENDENCY_ADDED = "DEPENDENCY_ADDED"
REPOSITORY_URL_CHANGED = "REPOSITORY_URL_CHANGED"

DEPENDENCIES_FIELD = "dependencies"
_TOKEN_MAX_CHARS = 64


def _bounded(text: str) -> str:
    """One printable line, bounded, so registry text cannot flood a finding."""
    cleaned = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in text)
    return cleaned[:_TOKEN_MAX_CHARS]


def _dependencies(metadata: dict[str, Any]) -> dict[str, str]:
    raw = metadata.get(DEPENDENCIES_FIELD)
    if not isinstance(raw, dict):
        return {}
    return {_bounded(str(key)): _bounded(str(value)) for key, value in raw.items()}


@registry.register(
    rule_id=DEPENDENCY_ADDED,
    rule_version=1,
    severity="low",
    ecosystems=("npm",),
    families=(RuleFamily.METADATA,),
    why_it_matters="A newly declared dependency widens what gets installed alongside the package.",
    common_benign_causes="A routine feature, refactor, or build tool update.",
)
def dependency_added(ctx: DiffContext) -> list[Finding]:
    """Detects dependency names present in the new registry version but not the old one.

    Reads ``versions[v].dependencies`` from ``metadata_before`` / ``metadata_after`` only.
    Names and version specs are bounded to one printable line, and one package-level
    finding is emitted per newly added dependency in sorted name order.

    Ignores deliberately: dependencies that were removed, version-spec changes to an
    existing dependency, ``devDependencies`` and every other registry field, malformed
    or non-object ``dependencies`` values, and the extracted ``package.json`` copy.
    TODO: ``devDependencies`` is not yet a rule (SPEC §3 / §10 A11).
    """
    before = _dependencies(ctx.metadata_before)
    after = _dependencies(ctx.metadata_after)
    return [
        scan.finding(
            ctx,
            rule_id=DEPENDENCY_ADDED,
            rule_version=1,
            severity=Severity.LOW,
            evidence=f"new dependency: {name}",
            details={"dependency": name, "section": DEPENDENCIES_FIELD},
        )
        for name in sorted(set(after) - set(before))
    ]


@registry.register(
    rule_id=REPOSITORY_URL_CHANGED,
    rule_version=1,
    severity="medium",
    ecosystems=("npm",),
    families=(RuleFamily.METADATA,),
    why_it_matters="The repository location is a provenance cue worth reviewing.",
    common_benign_causes="An organisation rename, a move to a monorepo, or a corrected URL.",
)
def repository_url_changed(ctx: DiffContext) -> list[Finding]:
    """Detects a changed ``repository`` field in the root ``package/package.json``.

    Uses the same defensive parser as the CLI's "package.json changes" section on both
    trees. Equivalent GitHub shorthand and URL forms are normalized before comparison;
    unknown formats stay raw. Evidence includes both bounded raw values.

    Ignores deliberately: an unchanged repository, a manifest missing on both sides, a
    malformed manifest (recorded as ``MANIFEST_INVALID_JSON`` by the caller, not here),
    the registry document's package-level ``repository.url`` snapshot, nested manifests,
    and any claim about why the field changed. TODO: doc-level ``repository.url`` is not
    a rule (SPEC §3 / §10 A11).
    """
    old_snapshot = read_root_manifest(ctx, "old")
    new_snapshot = read_root_manifest(ctx, "new")
    if old_snapshot.problem is not None or new_snapshot.problem is not None:
        return []
    old = old_snapshot.repository
    new = new_snapshot.repository
    if old == new:
        return []
    if (
        old is not None
        and new is not None
        and normalize_repository(old) == normalize_repository(new)
    ):
        return []
    if old is None:
        change = "added"
    elif new is None:
        change = "removed"
    else:
        change = "changed"
    return [
        scan.finding(
            ctx,
            rule_id=REPOSITORY_URL_CHANGED,
            rule_version=1,
            severity=Severity.MEDIUM,
            evidence=(
                f"repository field changed: {old if old is not None else '(absent)'}"
                f" -> {new if new is not None else '(absent)'}"
            ),
            details={"field": "repository", "change": change},
        )
    ]
