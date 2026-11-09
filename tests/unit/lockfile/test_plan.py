"""Deterministic, no-network planning for two parsed lockfiles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pkgwatch.config import LockConfig
from pkgwatch.lockfile import (
    ChangedPair,
    LockEntry,
    LockfileError,
    LockfileErrorCode,
    NewPackage,
    ParsedLockfile,
    PlanSide,
    PlanSkip,
    SkipReason,
    UnanalysedPackage,
    parse_lockfile,
    plan_lock_update,
)

REGISTRY = "https://registry.npmjs.org"


def _parsed(tmp_path: Path, name: str, packages: dict[str, Any]) -> Any:
    path = tmp_path / name
    path.write_text(json.dumps({"lockfileVersion": 3, "packages": packages}), encoding="utf-8")
    return parse_lockfile(path, limits=LockConfig())


def _resolved(name: str, version: str) -> str:
    return f"{REGISTRY}/{name}/-/{name}-{version}.tgz"


def test_plan_orders_changed_new_and_removed_packages(tmp_path: Path) -> None:
    old = _parsed(
        tmp_path,
        "old.json",
        {
            "node_modules/removed": {"version": "1.0.0", "resolved": _resolved("removed", "1")},
            "node_modules/b": {"version": "1.0.0", "resolved": _resolved("b", "1")},
            "node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")},
            "node_modules/same": {"version": "1.0.0", "resolved": _resolved("same", "1")},
        },
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/new-z": {"version": "2.0.0", "resolved": _resolved("new-z", "2")},
            "node_modules/a": {"version": "2.0.0", "resolved": _resolved("a", "2")},
            "node_modules/b": {"version": "1.0.0", "resolved": _resolved("b", "1")},
            "node_modules/same": {"version": "1.0.0", "resolved": _resolved("same", "1")},
            "node_modules/new-a": {
                "version": "1.0.0",
                "resolved": _resolved("new-a", "1"),
                "hasInstallScript": True,
            },
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == (ChangedPair(name="a", old_version="1.0.0", new_version="2.0.0"),)
    assert plan.new_packages == (
        NewPackage(name="new-a", version="1.0.0", has_install_script=True),
        NewPackage(name="new-z", version="2.0.0", has_install_script=None),
    )
    assert plan.removed_packages == ("removed",)
    assert plan.skipped == ()


def test_unsupported_sources_are_listed_never_dropped(tmp_path: Path) -> None:
    old = _parsed(tmp_path, "old.json", {})
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/git": {
                "version": "1.0.0",
                "resolved": "git+https://github.com/owner/repo.git",
                "hasInstallScript": True,
            },
            "node_modules/file": {"version": "1.0.0", "resolved": "file:../file"},
            "node_modules/http": {
                "version": "1.0.0",
                "resolved": "http://registry.npmjs.org/http/-/http-1.0.0.tgz",
            },
            "node_modules/other-host": {
                "version": "1.0.0",
                "resolved": "https://evil.example/other-host.tgz",
            },
            "node_modules/missing": {"version": "1.0.0"},
            "node_modules/linked": {"version": "1.0.0", "link": True},
            "node_modules/good": {"version": "1.0.0", "resolved": _resolved("good", "1")},
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == ()
    # L2c: a new package that cannot be analysed is unanalysed, never a clean result.
    assert plan.unanalysed == (
        UnanalysedPackage(
            name="file", old_version=None, new_version="1.0.0", reason=SkipReason.FILE_SOURCE
        ),
        UnanalysedPackage(
            name="git", old_version=None, new_version="1.0.0", reason=SkipReason.GIT_SOURCE
        ),
        UnanalysedPackage(
            name="http", old_version=None, new_version="1.0.0", reason=SkipReason.HTTP_SOURCE
        ),
        UnanalysedPackage(
            name="linked", old_version=None, new_version="1.0.0", reason=SkipReason.LINK_SOURCE
        ),
        UnanalysedPackage(
            name="missing",
            old_version=None,
            new_version="1.0.0",
            reason=SkipReason.MISSING_RESOLVED,
        ),
        UnanalysedPackage(
            name="other-host",
            old_version=None,
            new_version="1.0.0",
            reason=SkipReason.OTHER_HOST,
        ),
    )
    assert [item.name for item in plan.new_packages] == [
        "file",
        "git",
        "good",
        "http",
        "linked",
        "missing",
        "other-host",
    ]
    assert plan.skipped == ()


def test_new_packages_count_toward_max_pairs(tmp_path: Path) -> None:
    old = _parsed(tmp_path, "old.json", {})
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")},
            "node_modules/b": {"version": "1.0.0", "resolved": _resolved("b", "1")},
        },
    )

    with pytest.raises(LockfileError) as caught:
        plan_lock_update(old, new, limits=LockConfig(max_pairs=1))

    assert caught.value.code is LockfileErrorCode.TOO_MANY_PAIRS


def test_no_new_keeps_new_packages_out_of_the_limit_and_unanalysed(tmp_path: Path) -> None:
    old = _parsed(tmp_path, "old.json", {})
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")},
            "node_modules/b": {"version": "1.0.0", "resolved": _resolved("b", "1")},
            "node_modules/git": {
                "version": "1.0.0",
                "resolved": "git+https://github.com/owner/repo.git",
            },
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig(max_pairs=1), analyse_new=False)

    assert plan.changed_pairs == ()
    assert plan.unanalysed == ()
    assert [item.name for item in plan.new_packages] == ["a", "b", "git"]


def test_a_changed_pair_with_one_unsupported_side_is_not_analysed(tmp_path: Path) -> None:
    old = _parsed(
        tmp_path,
        "old.json",
        {"node_modules/x": {"version": "1.0.0", "resolved": _resolved("x", "1")}},
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/x": {
                "version": "2.0.0",
                "resolved": "git+ssh://git@github.com/owner/x.git",
            }
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == ()
    assert plan.unanalysed == (
        UnanalysedPackage(
            name="x",
            old_version="1.0.0",
            new_version="2.0.0",
            reason=SkipReason.GIT_SOURCE,
        ),
    )
    assert plan.skipped == (
        PlanSkip(
            side=PlanSide.OLD,
            name="x",
            version="1.0.0",
            reason=SkipReason.PAIR_SOURCE_UNSUPPORTED,
        ),
        PlanSkip(side=PlanSide.NEW, name="x", version="2.0.0", reason=SkipReason.GIT_SOURCE),
    )


def test_balanced_multi_version_names_pair_index_wise_in_version_order(tmp_path: Path) -> None:
    # SPEC §6.4: the changed sets are equal in size, so version order decides the pairing
    # lowest→lowest. Insertion order in the JSON is the reverse, to prove the sort happens.
    old = _parsed(
        tmp_path,
        "old.json",
        {
            "node_modules/a/node_modules/a": {
                "version": "2.0.0",
                "resolved": _resolved("a", "2"),
            },
            "node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")},
        },
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/a/node_modules/a": {
                "version": "2.1.0",
                "resolved": _resolved("a", "2.1"),
            },
            "node_modules/a": {"version": "1.1.0", "resolved": _resolved("a", "1.1")},
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == (
        ChangedPair(name="a", old_version="1.0.0", new_version="1.1.0"),
        ChangedPair(name="a", old_version="2.0.0", new_version="2.1.0"),
    )
    assert plan.unanalysed == ()
    assert plan.skipped == ()


def test_balanced_changed_subset_of_a_multi_version_name_pairs(tmp_path: Path) -> None:
    # The 2.0.0 entry exists on both sides; only 1.0.0 (gone) and 3.0.0 (new) changed,
    # and those two form a balanced one-element pairing.
    old = _parsed(
        tmp_path,
        "old.json",
        {
            "node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")},
            "node_modules/a/node_modules/a": {
                "version": "2.0.0",
                "resolved": _resolved("a", "2"),
            },
        },
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/a": {"version": "2.0.0", "resolved": _resolved("a", "2")},
            "node_modules/a/node_modules/a": {
                "version": "3.0.0",
                "resolved": _resolved("a", "3"),
            },
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == (ChangedPair(name="a", old_version="1.0.0", new_version="3.0.0"),)
    assert plan.unanalysed == ()
    assert plan.skipped == ()


def test_unbalanced_multi_version_sets_keep_multiple_versions(tmp_path: Path) -> None:
    old = _parsed(
        tmp_path,
        "old.json",
        {"node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")}},
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/a": {"version": "1.1.0", "resolved": _resolved("a", "1.1")},
            "node_modules/a/node_modules/a": {
                "version": "2.0.0",
                "resolved": _resolved("a", "2"),
            },
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == ()
    assert plan.unanalysed == (
        UnanalysedPackage(
            name="a",
            old_version=None,
            new_version=None,
            reason=SkipReason.MULTIPLE_VERSIONS,
        ),
    )
    assert plan.skipped == (
        PlanSkip(
            side=PlanSide.OLD,
            name="a",
            version="1.0.0",
            reason=SkipReason.MULTIPLE_VERSIONS,
        ),
        PlanSkip(
            side=PlanSide.NEW,
            name="a",
            version="1.1.0",
            reason=SkipReason.MULTIPLE_VERSIONS,
        ),
        PlanSkip(
            side=PlanSide.NEW,
            name="a",
            version="2.0.0",
            reason=SkipReason.MULTIPLE_VERSIONS,
        ),
    )


def test_balanced_pair_with_an_unsupported_source_stays_unanalysed(tmp_path: Path) -> None:
    old = _parsed(
        tmp_path,
        "old.json",
        {
            "node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")},
            "node_modules/a/node_modules/a": {
                "version": "2.0.0",
                "resolved": _resolved("a", "2"),
            },
        },
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/a": {"version": "1.1.0", "resolved": _resolved("a", "1.1")},
            "node_modules/a/node_modules/a": {
                "version": "2.1.0",
                "resolved": "git+https://github.com/owner/a.git",
            },
        },
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == (ChangedPair(name="a", old_version="1.0.0", new_version="1.1.0"),)
    assert plan.unanalysed == (
        UnanalysedPackage(
            name="a",
            old_version="2.0.0",
            new_version="2.1.0",
            reason=SkipReason.GIT_SOURCE,
        ),
    )
    assert plan.skipped == (
        PlanSkip(
            side=PlanSide.OLD,
            name="a",
            version="2.0.0",
            reason=SkipReason.PAIR_SOURCE_UNSUPPORTED,
        ),
        PlanSkip(side=PlanSide.NEW, name="a", version="2.1.0", reason=SkipReason.GIT_SOURCE),
    )


def test_unparseable_version_in_a_multi_version_name_falls_back() -> None:
    # The parser validates versions, so this is only reachable through a directly built
    # ParsedLockfile; the plan must not guess an order it cannot parse.
    old = ParsedLockfile(
        lockfile_version=3,
        entries=(
            LockEntry(name="a", version="1.0.0", resolved=_resolved("a", "1")),
            LockEntry(name="a", version="bogus", resolved=_resolved("a", "bogus")),
        ),
        skipped=(),
    )
    new = ParsedLockfile(
        lockfile_version=3,
        entries=(
            LockEntry(name="a", version="2.0.0", resolved=_resolved("a", "2")),
            LockEntry(name="a", version="3.0.0", resolved=_resolved("a", "3")),
        ),
        skipped=(),
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.changed_pairs == ()
    assert plan.unanalysed == (
        UnanalysedPackage(
            name="a",
            old_version=None,
            new_version=None,
            reason=SkipReason.MULTIPLE_VERSIONS,
        ),
    )


def test_parser_skips_keep_their_lockfile_side(tmp_path: Path) -> None:
    old = _parsed(
        tmp_path,
        "old.json",
        {"node_modules/old-bad": {"version": "^1.0.0"}},
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {"node_modules/BadName": {"version": "1.0.0"}},
    )

    plan = plan_lock_update(old, new, limits=LockConfig())

    assert plan.skipped == (
        PlanSkip(
            side=PlanSide.OLD,
            name="old-bad",
            version="^1.0.0",
            reason=SkipReason.INVALID_VERSION,
        ),
        PlanSkip(
            side=PlanSide.NEW,
            name="BadName",
            version="1.0.0",
            reason=SkipReason.INVALID_NAME,
        ),
    )


def test_too_many_pairs_fails_instead_of_truncating(tmp_path: Path) -> None:
    old = _parsed(
        tmp_path,
        "old.json",
        {
            "node_modules/a": {"version": "1.0.0", "resolved": _resolved("a", "1")},
            "node_modules/b": {"version": "1.0.0", "resolved": _resolved("b", "1")},
        },
    )
    new = _parsed(
        tmp_path,
        "new.json",
        {
            "node_modules/a": {"version": "2.0.0", "resolved": _resolved("a", "2")},
            "node_modules/b": {"version": "2.0.0", "resolved": _resolved("b", "2")},
        },
    )

    with pytest.raises(LockfileError) as caught:
        plan_lock_update(old, new, limits=LockConfig(max_pairs=1))

    assert caught.value.code is LockfileErrorCode.TOO_MANY_PAIRS
