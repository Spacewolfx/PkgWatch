"""Deterministic, no-network planning for two parsed lockfiles (SPEC §9.1).

Only a package name present on both sides can become a changed pair. A name with one
version per side pairs directly. A name with several versions pairs when the changed
sets (versions present on exactly one side) are the same size on both sides: SPEC §6.4's
version order sorts each set and the pairing is index-wise, lowest to lowest. Any other
multi-version shape stays a ``MULTIPLE_VERSIONS`` skip rather than inventing a pairing.
Source support reuses ``fetch.npm``'s registry allow-list; nothing here fetches,
executes or resolves a package.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from enum import StrEnum

from pkgwatch import version
from pkgwatch.config import LockConfig
from pkgwatch.fetch.npm import is_registry_url
from pkgwatch.lockfile.parser import (
    LockEntry,
    LockfileError,
    LockfileErrorCode,
    ParsedLockfile,
    SkippedEntry,
    SkipReason,
)
from pkgwatch.models import Ecosystem

_SIDE_ORDER = {"old": 0, "new": 1}


class PlanSide(StrEnum):
    OLD = "old"
    NEW = "new"


@dataclass(frozen=True)
class ChangedPair:
    name: str
    old_version: str
    new_version: str


@dataclass(frozen=True)
class NewPackage:
    name: str
    version: str
    has_install_script: bool | None


@dataclass(frozen=True)
class PlanSkip:
    side: PlanSide
    name: str
    version: str | None
    reason: SkipReason


@dataclass(frozen=True)
class UnanalysedPackage:
    """A changed or brand-new package that could not be analysed; never a clean result."""

    name: str
    old_version: str | None
    new_version: str | None
    reason: SkipReason


@dataclass(frozen=True)
class LockPlan:
    old_lockfile_version: int
    new_lockfile_version: int
    changed_pairs: tuple[ChangedPair, ...]
    new_packages: tuple[NewPackage, ...]
    removed_packages: tuple[str, ...]
    skipped: tuple[PlanSkip, ...]
    unanalysed: tuple[UnanalysedPackage, ...]


def plan_lock_update(
    old: ParsedLockfile,
    new: ParsedLockfile,
    *,
    limits: LockConfig,
    analyse_new: bool = True,
) -> LockPlan:
    old_by_name = _by_name(old.entries)
    new_by_name = _by_name(new.entries)
    old_skip_reason = _first_skip_reason(old.skipped)
    new_skip_reason = _first_skip_reason(new.skipped)

    pairs: list[ChangedPair] = []
    added: list[NewPackage] = []
    removed: list[str] = []
    unanalysed: list[UnanalysedPackage] = []
    skipped: list[PlanSkip] = [
        PlanSkip(PlanSide.OLD, item.name, item.version, item.reason) for item in old.skipped
    ]
    skipped.extend(
        PlanSkip(PlanSide.NEW, item.name, item.version, item.reason) for item in new.skipped
    )

    for name in sorted(old_by_name.keys() | new_by_name.keys()):
        old_entries = old_by_name.get(name, {})
        new_entries = new_by_name.get(name, {})

        if not new_entries:
            # The new side exists but every version failed parsing: this is a changed
            # package we cannot read, not a removal (SPEC §9.1 L2c). A name absent from
            # both the entries and the skips is a genuine removal.
            new_reason = new_skip_reason.get(name)
            if new_reason is not None:
                unanalysed.append(
                    UnanalysedPackage(name, _sole_version(old_entries), None, new_reason)
                )
            else:
                removed.append(name)
            continue
        if not old_entries:
            # Symmetric: the old side failed parsing, so the package had a predecessor we
            # could not read. It is unanalysed, never a clean brand-new result.
            old_reason = old_skip_reason.get(name)
            if old_reason is not None:
                unanalysed.append(
                    UnanalysedPackage(name, None, _sole_version(new_entries), old_reason)
                )
                continue
            for version in sorted(new_entries):
                entry = new_entries[version]
                added.append(NewPackage(name, version, entry.has_install_script))
                reason = _source_reason(entry)
                if reason is not None and analyse_new:
                    unanalysed.append(UnanalysedPackage(name, None, version, reason))
            continue

        old_versions = set(old_entries)
        new_versions = set(new_entries)
        changed_old = old_versions - new_versions
        changed_new = new_versions - old_versions
        if not changed_old and not changed_new:
            # The version set is identical, but a tarball republished at the same version
            # changes its integrity hash. We fetch by version and cannot retrieve the
            # historical tarball to diff it, so surface the swap as unanalysed rather than
            # a silent "no change" (C2). Both hashes must be present to claim a swap.
            for version in sorted(old_versions):
                old_integrity = old_entries[version].integrity
                new_integrity = new_entries[version].integrity
                if (
                    old_integrity is not None
                    and new_integrity is not None
                    and old_integrity != new_integrity
                ):
                    unanalysed.append(
                        UnanalysedPackage(name, version, version, SkipReason.INTEGRITY_CHANGED)
                    )
            continue

        if len(old_versions) > 1 or len(new_versions) > 1:
            ordered = (
                _version_ordered(changed_old, changed_new)
                if changed_old and len(changed_old) == len(changed_new)
                else None
            )
            if ordered is not None:
                for old_version, new_version in ordered:
                    _emit_pair(
                        name,
                        old_version,
                        new_version,
                        old_entries[old_version],
                        new_entries[new_version],
                        pairs=pairs,
                        unanalysed=unanalysed,
                        skipped=skipped,
                    )
                continue
            unanalysed.append(UnanalysedPackage(name, None, None, SkipReason.MULTIPLE_VERSIONS))
            skipped.extend(
                PlanSkip(PlanSide.OLD, name, item, SkipReason.MULTIPLE_VERSIONS)
                for item in sorted(changed_old)
            )
            skipped.extend(
                PlanSkip(PlanSide.NEW, name, item, SkipReason.MULTIPLE_VERSIONS)
                for item in sorted(changed_new)
            )
            continue

        (old_version,) = old_versions
        (new_version,) = new_versions
        _emit_pair(
            name,
            old_version,
            new_version,
            old_entries[old_version],
            new_entries[new_version],
            pairs=pairs,
            unanalysed=unanalysed,
            skipped=skipped,
        )

    # New packages are analysis work too (SPEC §9.1), unless --no-new opted out of them.
    workload = len(pairs) + (len(added) if analyse_new else 0)
    if workload > limits.max_pairs:
        raise LockfileError(LockfileErrorCode.TOO_MANY_PAIRS)

    return LockPlan(
        old_lockfile_version=old.lockfile_version,
        new_lockfile_version=new.lockfile_version,
        changed_pairs=tuple(sorted(pairs, key=lambda pair: (pair.name, pair.old_version))),
        new_packages=tuple(added),
        removed_packages=tuple(removed),
        skipped=_ordered_skips(skipped),
        unanalysed=tuple(
            sorted(
                unanalysed,
                key=lambda item: (
                    item.name,
                    item.old_version or "",
                    item.new_version or "",
                    item.reason.value,
                ),
            )
        ),
    )


def _by_name(entries: tuple[LockEntry, ...]) -> dict[str, dict[str, LockEntry]]:
    grouped: dict[str, dict[str, LockEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.name, {})[entry.version] = entry
    return grouped


def _first_skip_reason(skipped: tuple[SkippedEntry, ...]) -> dict[str, SkipReason]:
    """The first parser-skip reason per name, in the parser's already-sorted order."""
    reasons: dict[str, SkipReason] = {}
    for item in skipped:
        reasons.setdefault(item.name, item.reason)
    return reasons


def _sole_version(entries: dict[str, LockEntry]) -> str | None:
    """The one version when a side has exactly one; None when it has several or none."""
    if len(entries) == 1:
        return next(iter(entries))
    return None


def _ordered_skips(items: list[PlanSkip]) -> tuple[PlanSkip, ...]:
    unique = {(item.side, item.name, item.version, item.reason): item for item in items}
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                _SIDE_ORDER[item.side.value],
                item.name,
                item.version or "",
                item.reason.value,
            ),
        )
    )


def _version_ordered(old_set: set[str], new_set: set[str]) -> list[tuple[str, str]] | None:
    """SPEC §6.4 pairing: sort both changed sets by version, zip index-wise.

    Returns ``None`` when any version is unparseable — then no order is claimed and the
    caller keeps the ``MULTIPLE_VERSIONS`` fallback. Ties on equal precedence break by
    text, so the pairing is deterministic.
    """

    def order(text: str) -> tuple[tuple[object, ...], str]:
        return (version.parse(Ecosystem.NPM, text).key, text)

    try:
        old_sorted = sorted(old_set, key=order)
        new_sorted = sorted(new_set, key=order)
    except version.UnsupportedVersion:
        return None
    return list(zip(old_sorted, new_sorted, strict=True))


def _emit_pair(
    name: str,
    old_version: str,
    new_version: str,
    old_entry: LockEntry,
    new_entry: LockEntry,
    *,
    pairs: list[ChangedPair],
    unanalysed: list[UnanalysedPackage],
    skipped: list[PlanSkip],
) -> None:
    """Classify one candidate pairing: analysable, or unanalysed with per-side skips."""
    old_reason = _source_reason(old_entry)
    new_reason = _source_reason(new_entry)
    if old_reason is None and new_reason is None:
        pairs.append(ChangedPair(name, old_version, new_version))
        return

    unanalysed.append(
        UnanalysedPackage(
            name,
            old_version,
            new_version,
            new_reason or old_reason or SkipReason.PAIR_SOURCE_UNSUPPORTED,
        )
    )
    skipped.append(
        PlanSkip(
            PlanSide.OLD,
            name,
            old_version,
            old_reason if old_reason is not None else SkipReason.PAIR_SOURCE_UNSUPPORTED,
        )
    )
    skipped.append(
        PlanSkip(
            PlanSide.NEW,
            name,
            new_version,
            new_reason if new_reason is not None else SkipReason.PAIR_SOURCE_UNSUPPORTED,
        )
    )


def _source_reason(entry: LockEntry) -> SkipReason | None:
    if entry.link:
        return SkipReason.LINK_SOURCE
    resolved = entry.resolved
    if resolved is None:
        return SkipReason.MISSING_RESOLVED
    try:
        scheme = urllib.parse.urlsplit(resolved).scheme.casefold()
    except ValueError:
        return SkipReason.INVALID_SOURCE
    if scheme.startswith("git") or resolved.startswith("git+"):
        return SkipReason.GIT_SOURCE
    if scheme == "file":
        return SkipReason.FILE_SOURCE
    if scheme == "http":
        return SkipReason.HTTP_SOURCE
    if is_registry_url(resolved):
        return None
    if scheme == "https":
        return SkipReason.OTHER_HOST
    return SkipReason.INVALID_SOURCE
