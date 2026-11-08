"""The lock runner composes the existing pipeline per changed pair (SPEC §9.1).

Everything here runs against the injected offline registry: no sockets, no live registry,
and no package content is ever executed, imported or installed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from pkgwatch.config import Config
from pkgwatch.fetch.cache import DownloadCache
from pkgwatch.fetch.npm import FetchErrorCode, expected_digest
from pkgwatch.lock import run_lock
from pkgwatch.lockfile import LockfileError, LockfileErrorCode
from pkgwatch.models import RejectionCode
from tests.support.lockfiles import node_modules, registry_entry, write_lockfile
from tests.support.npm_registry import (
    FakeRegistry,
    MultiRegistry,
    case_registry,
    dist_for,
    package_registry,
    tarball_bytes,
)

BENIGN = "npm_benign_bump"
INSTALLER = "npm_synthetic_installer"
OLD = "1.0.0"
NEW = "1.1.0"

FOUR_RULES = {
    "NPM_INSTALL_SCRIPT_ADDED",
    "JS_CHILD_PROCESS_ADDED",
    "DYNAMIC_EVAL_ADDED",
    "ENV_ENUMERATION_ADDED",
}
INSTALLER_SCORE = 94


def _pair_lockfiles(tmp_path: Path, registries: Mapping[str, FakeRegistry]) -> tuple[Path, Path]:
    old: dict[str, Any] = {}
    new: dict[str, Any] = {}
    for name, registry in registries.items():
        old[node_modules(name)] = registry_entry(registry, OLD)
        new[node_modules(name)] = registry_entry(registry, NEW)
    return (
        write_lockfile(tmp_path / "old.json", old),
        write_lockfile(tmp_path / "new.json", new),
    )


def _set_metadata_dependencies(
    registry: FakeRegistry,
    *,
    old: dict[str, str] | None = None,
    new: dict[str, str] | None = None,
) -> None:
    """Serve a registry document whose version docs declare the given dependencies."""
    document = registry.document()
    if old is not None:
        document["versions"][registry.old_version]["dependencies"] = old
    if new is not None:
        document["versions"][registry.new_version]["dependencies"] = new
    registry.doc_override = json.dumps(document).encode("utf-8")


def test_changed_pairs_run_through_the_existing_pipeline(tmp_path: Path) -> None:
    benign = case_registry(tmp_path, BENIGN, name="benign-pkg")
    installer = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client = MultiRegistry([benign, installer])
    old_lock, new_lock = _pair_lockfiles(
        tmp_path, {"benign-pkg": benign, "installer-pkg": installer}
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    assert [(item.name, item.old_version, item.new_version) for item in result.pairs] == [
        ("benign-pkg", OLD, NEW),
        ("installer-pkg", OLD, NEW),
    ]
    assert result.incomplete is False

    quiet, noisy = result.pairs
    assert quiet.error is None
    assert quiet.findings == ()
    assert quiet.score == 0
    assert quiet.digests == ("integrity", "integrity")

    assert noisy.error is None
    assert {item.rule_id for item in noisy.findings} == FOUR_RULES
    assert noisy.score == INSTALLER_SCORE
    assert noisy.files[0] + noisy.files[1] + noisy.files[2] > 0


def test_a_failed_pair_is_recorded_and_the_others_still_complete(tmp_path: Path) -> None:
    benign = case_registry(tmp_path, BENIGN, name="benign-pkg")
    broken = case_registry(tmp_path, INSTALLER, name="broken-pkg")
    broken.new_dist = dist_for(broken.new_tarball, corrupt=True)
    client = MultiRegistry([benign, broken])
    old_lock, new_lock = _pair_lockfiles(tmp_path, {"benign-pkg": benign, "broken-pkg": broken})

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    by_name = {item.name: item for item in result.pairs}
    assert by_name["benign-pkg"].error is None
    failed = by_name["broken-pkg"]
    assert failed.error == FetchErrorCode.DIGEST_MISMATCH.value
    assert failed.findings == ()
    assert failed.score == 0
    assert result.incomplete is True


def test_a_sandbox_rejection_is_recorded_as_a_pair_error(tmp_path: Path) -> None:
    escaping = case_registry(tmp_path, BENIGN, name="escape-pkg")
    payload = tarball_bytes(tmp_path, BENIGN, "new", escape=True)
    escaping.new_tarball = payload
    escaping.new_dist = dist_for(payload)
    client = MultiRegistry([escaping])
    old_lock, new_lock = _pair_lockfiles(tmp_path, {"escape-pkg": escaping})

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    assert result.pairs[0].error == RejectionCode.PATH_TRAVERSAL.value
    assert result.incomplete is True


def test_ignored_rules_leave_findings_score_and_the_counts(tmp_path: Path) -> None:
    installer = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client = MultiRegistry([installer])
    old_lock, new_lock = _pair_lockfiles(tmp_path, {"installer-pkg": installer})

    result = run_lock(
        old_lock=old_lock,
        new_lock=new_lock,
        config=Config(),
        client=client,
        ignored=["DYNAMIC_EVAL_ADDED"],
    )

    pair = result.pairs[0]
    assert "DYNAMIC_EVAL_ADDED" not in {item.rule_id for item in pair.findings}
    assert pair.ignored == (("DYNAMIC_EVAL_ADDED", 1),)
    assert pair.score < INSTALLER_SCORE


def test_pair_order_is_deterministic_when_pairs_run_concurrently(tmp_path: Path) -> None:
    registries = {
        name: case_registry(tmp_path, BENIGN, name=name) for name in ("c-pkg", "a-pkg", "b-pkg")
    }
    client = MultiRegistry(list(registries.values()))
    old_lock, new_lock = _pair_lockfiles(tmp_path, registries)
    config = Config.from_toml("[lock]\nconcurrency = 3\n")

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=config, client=client)

    assert [item.name for item in result.pairs] == ["a-pkg", "b-pkg", "c-pkg"]
    assert all(item.error is None for item in result.pairs)


def test_the_plan_sections_are_carried_through(tmp_path: Path) -> None:
    kept = case_registry(tmp_path, BENIGN, name="kept-pkg")
    client = MultiRegistry([kept])
    old_lock = write_lockfile(
        tmp_path / "old.json",
        {
            node_modules("kept-pkg"): registry_entry(kept, OLD),
            node_modules("gone-pkg"): registry_entry(kept, OLD),
        },
    )
    new_lock = write_lockfile(
        tmp_path / "new.json",
        {
            node_modules("kept-pkg"): registry_entry(kept, NEW),
            node_modules("added-pkg"): {
                "version": "2.0.0",
                "resolved": "git+https://github.com/owner/added-pkg.git",
                "hasInstallScript": True,
            },
        },
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    assert result.plan.removed_packages == ("gone-pkg",)
    assert [
        (item.name, item.version, item.has_install_script) for item in result.plan.new_packages
    ] == [("added-pkg", "2.0.0", True)]
    assert [(item.name, item.reason.value) for item in result.plan.unanalysed] == [
        ("added-pkg", "GIT_SOURCE")
    ]
    assert result.plan.skipped == ()
    assert result.new_analyses == ()
    assert [item.name for item in result.pairs] == ["kept-pkg"]


def test_a_new_package_is_analysed_against_an_empty_tree(tmp_path: Path) -> None:
    installer = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client = MultiRegistry([installer])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("installer-pkg"): registry_entry(installer, NEW)}
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    assert result.pairs == ()
    assert result.new_analysed is True
    assert result.incomplete is False
    (analysis,) = result.new_analyses
    assert (analysis.name, analysis.version) == ("installer-pkg", NEW)
    assert analysis.error is None
    assert {item.rule_id for item in analysis.findings} >= FOUR_RULES
    assert analysis.score > 0
    assert analysis.digest == "integrity"
    # Only the one version is fetched: there is no predecessor to download.
    assert client.requests == [installer.doc_url, installer.new_url]


def test_family_four_of_a_new_package_is_informational_not_scored(tmp_path: Path) -> None:
    registry = package_registry(
        tmp_path,
        "meta-pkg",
        old_version=OLD,
        new_version=NEW,
        old_files={"package.json": b'{"name":"meta-pkg","version":"1.0.0"}'},
        new_files={
            "package.json": (
                b'{"name":"meta-pkg","version":"1.1.0",'
                b'"repository":"https://github.com/owner/meta-pkg"}'
            ),
            "index.js": b"module.exports = 1;\n",
        },
    )
    _set_metadata_dependencies(registry, new={"left-pad": "^1.0.0"})
    client = MultiRegistry([registry])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("meta-pkg"): registry_entry(registry, NEW)}
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    (analysis,) = result.new_analyses
    assert analysis.error is None
    assert analysis.findings == ()
    assert analysis.score == 0
    assert analysis.informational == (
        ("DEPENDENCY_ADDED", 1),
        ("REPOSITORY_URL_CHANGED", 1),
    )


def test_family_three_of_a_new_package_stays_a_finding(tmp_path: Path) -> None:
    blob = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" * 4
    registry = package_registry(
        tmp_path,
        "blob-pkg",
        old_version=OLD,
        new_version=NEW,
        old_files={"package.json": b'{"name":"blob-pkg","version":"1.0.0"}'},
        new_files={
            "package.json": b'{"name":"blob-pkg","version":"1.1.0"}',
            "index.js": b'const blob = "' + blob + b'";\n',
        },
    )
    client = MultiRegistry([registry])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("blob-pkg"): registry_entry(registry, NEW)}
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    (analysis,) = result.new_analyses
    assert analysis.error is None
    assert "BASE64_BLOB_PRESENT" in {item.rule_id for item in analysis.findings}
    assert analysis.informational == ()


def test_a_changed_pair_keeps_family_four_findings_scored(tmp_path: Path) -> None:
    registry = package_registry(
        tmp_path,
        "dep-pkg",
        old_version=OLD,
        new_version=NEW,
        old_files={
            "package.json": b'{"name":"dep-pkg","version":"1.0.0"}',
            "index.js": b"module.exports = 1;\n",
        },
        new_files={
            "package.json": b'{"name":"dep-pkg","version":"1.1.0"}',
            "index.js": b"module.exports = 1;\n",
        },
    )
    _set_metadata_dependencies(
        registry, old={"shared": "1.0.0"}, new={"shared": "1.0.0", "extra": "2.0.0"}
    )
    client = MultiRegistry([registry])
    old_lock = write_lockfile(
        tmp_path / "old.json", {node_modules("dep-pkg"): registry_entry(registry, OLD)}
    )
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("dep-pkg"): registry_entry(registry, NEW)}
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    (pair,) = result.pairs
    assert pair.error is None
    assert {item.rule_id for item in pair.findings} == {"DEPENDENCY_ADDED"}
    assert pair.score > 0


def test_a_failed_new_package_makes_the_run_incomplete(tmp_path: Path) -> None:
    broken = case_registry(tmp_path, INSTALLER, name="broken-pkg")
    broken.new_dist = dist_for(broken.new_tarball, corrupt=True)
    client = MultiRegistry([broken])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("broken-pkg"): registry_entry(broken, NEW)}
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    (analysis,) = result.new_analyses
    assert analysis.error == FetchErrorCode.DIGEST_MISMATCH.value
    assert analysis.findings == ()
    assert analysis.score == 0
    assert result.incomplete is True


def test_analyse_new_false_lists_new_packages_without_fetching_them(tmp_path: Path) -> None:
    installer = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client = MultiRegistry([installer])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("installer-pkg"): registry_entry(installer, NEW)}
    )

    result = run_lock(
        old_lock=old_lock, new_lock=new_lock, config=Config(), client=client, analyse_new=False
    )

    assert result.new_analysed is False
    assert result.new_analyses == ()
    assert result.incomplete is False
    assert [item.name for item in result.plan.new_packages] == ["installer-pkg"]
    assert client.requests == []


def test_too_many_pairs_fails_before_any_fetch(tmp_path: Path) -> None:
    first = case_registry(tmp_path, BENIGN, name="a-pkg")
    second = case_registry(tmp_path, BENIGN, name="b-pkg")
    client = MultiRegistry([first, second])
    old_lock, new_lock = _pair_lockfiles(tmp_path, {"a-pkg": first, "b-pkg": second})

    with pytest.raises(LockfileError) as caught:
        run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client, max_pairs=1)

    assert caught.value.code is LockfileErrorCode.TOO_MANY_PAIRS
    assert client.requests == []


def test_an_unsupported_lockfile_version_fails_before_any_fetch(tmp_path: Path) -> None:
    kept = case_registry(tmp_path, BENIGN, name="kept-pkg")
    client = MultiRegistry([kept])
    old_lock = write_lockfile(
        tmp_path / "old.json",
        {node_modules("kept-pkg"): registry_entry(kept, OLD)},
        lockfile_version=1,
    )
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("kept-pkg"): registry_entry(kept, NEW)}
    )

    with pytest.raises(LockfileError) as caught:
        run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    assert caught.value.code is LockfileErrorCode.LOCKFILE_UNSUPPORTED_VERSION
    assert client.requests == []


def test_a_package_with_several_versions_is_not_paired(tmp_path: Path) -> None:
    outer = package_registry(
        tmp_path,
        "dup-pkg",
        old_version=OLD,
        new_version="2.0.0",
        old_files={"package.json": b'{"name":"dup-pkg","version":"1.0.0"}'},
        new_files={"package.json": b'{"name":"dup-pkg","version":"2.0.0"}'},
    )
    client = MultiRegistry([outer])
    old_lock = write_lockfile(
        tmp_path / "old.json",
        {
            node_modules("dup-pkg"): registry_entry(outer, OLD),
            f"{node_modules('dup-pkg')}/node_modules/dup-pkg": registry_entry(outer, "2.0.0"),
        },
    )
    new_lock = write_lockfile(
        tmp_path / "new.json",
        {node_modules("dup-pkg"): registry_entry(outer, "2.0.0")},
    )

    result = run_lock(old_lock=old_lock, new_lock=new_lock, config=Config(), client=client)

    assert result.pairs == ()
    assert [(item.name, item.reason.value) for item in result.plan.skipped] == [
        ("dup-pkg", "MULTIPLE_VERSIONS")
    ]
    assert client.requests == []


def test_the_download_cache_avoids_refetching_verified_tarballs(tmp_path: Path) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock, new_lock = _pair_lockfiles(tmp_path, {"benign-pkg": registry})
    cache = DownloadCache(tmp_path / "cache")
    config = Config.from_toml("[lock]\nrequest_delay_seconds = 0.0\n")
    tarballs = {registry.old_url, registry.new_url}

    first = run_lock(
        old_lock=old_lock, new_lock=new_lock, config=config, client=client, cache=cache
    )
    assert tarballs <= set(client.requests)

    client.requests.clear()
    second = run_lock(
        old_lock=old_lock, new_lock=new_lock, config=config, client=client, cache=cache
    )

    assert tarballs.isdisjoint(client.requests)
    assert second.pairs[0].error is None
    assert second.pairs[0].score == first.pairs[0].score


def test_a_corrupt_cache_entry_is_replaced_from_the_registry(tmp_path: Path) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock, new_lock = _pair_lockfiles(tmp_path, {"benign-pkg": registry})
    cache = DownloadCache(tmp_path / "cache")
    config = Config.from_toml("[lock]\nrequest_delay_seconds = 0.0\n")
    run_lock(old_lock=old_lock, new_lock=new_lock, config=config, client=client, cache=cache)

    expected = expected_digest(registry.new_dist)
    path = cache.path_for(expected)
    path.write_bytes(b"tampered")
    client.requests.clear()

    result = run_lock(
        old_lock=old_lock, new_lock=new_lock, config=config, client=client, cache=cache
    )

    assert registry.new_url in client.requests
    assert path.read_bytes() == registry.new_tarball
    assert result.pairs[0].error is None
