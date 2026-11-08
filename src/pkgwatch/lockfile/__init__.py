"""Untrusted npm lockfile parsing and planning (SPEC §9.1)."""

from __future__ import annotations

from pkgwatch.lockfile.parser import (
    LockEntry,
    LockfileError,
    LockfileErrorCode,
    ParsedLockfile,
    SkippedEntry,
    SkipReason,
    parse_lockfile,
)
from pkgwatch.lockfile.plan import (
    ChangedPair,
    LockPlan,
    NewPackage,
    PlanSide,
    PlanSkip,
    UnanalysedPackage,
    plan_lock_update,
)

__all__ = [
    "ChangedPair",
    "LockEntry",
    "LockPlan",
    "LockfileError",
    "LockfileErrorCode",
    "NewPackage",
    "ParsedLockfile",
    "PlanSide",
    "PlanSkip",
    "SkipReason",
    "SkippedEntry",
    "UnanalysedPackage",
    "parse_lockfile",
    "plan_lock_update",
]
