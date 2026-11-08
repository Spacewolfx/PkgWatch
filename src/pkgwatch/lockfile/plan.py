"""Deterministic, no-network planning for two parsed lockfiles (SPEC §9.1).

Only a package name present on both sides can become a changed pair, and only when each
side holds exactly one version. Names with several versions are reported as skips rather
than inventing an old→new pairing: SPEC §6.4's version order does not exist yet, so no
upgrade/downgrade direction is claimed. Source support reuses ``fetch.npm``'s registry
allow-list; nothing here fetches, executes or resolves a package.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from enum import StrEnum

from pkgwatch.config import LockConfig
from pkgwatch.fetch.npm import is_registry_url
from pkgwatch.lockfile.parser import (
    LockEntry,
    LockfileError,
    LockfileErrorCode,
    ParsedLockfile,
    SkipReason,
)

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
            removed.append(name)
            continue
        if not old_entries:
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
            continue

        if len(old_versions) > 1 or len(new_versions) > 1:
            unanalysed.append(UnanalysedPackage(name, None, None, SkipReason.MULTIPLE_VERSIONS))
            skipped.extend(
                PlanSkip(PlanSide.OLD, name, version, SkipReason.MULTIPLE_VERSIONS)
                for version in sorted(changed_old)
            )
            skipped.extend(
                PlanSkip(PlanSide.NEW, name, version, SkipReason.MULTIPLE_VERSIONS)
                for version in sorted(changed_new)
            )
            continue

        (old_version,) = old_versions
        (new_version,) = new_versions
        old_reason = _source_reason(old_entries[old_version])
        new_reason = _source_reason(new_entries[new_version])
        if old_reason is None and new_reason is None:
            pairs.append(ChangedPair(name, old_version, new_version))
            continue

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
