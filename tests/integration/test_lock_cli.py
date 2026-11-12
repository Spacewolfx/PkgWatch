"""The ``pkgwatch lock`` command, end to end, against an injected offline registry.

Two lockfiles are written to ``tmp_path`` and every tarball comes from the committed
synthetic fixture trees. No live registry, no sockets, and no package content is run.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

import pytest

from pkgwatch import cli
from pkgwatch.cli import DISCLAIMER
from pkgwatch.config import Config
from pkgwatch.fetch.npm import HttpResponse
from tests.support.lockfiles import node_modules, registry_entry, write_lockfile
from tests.support.npm_registry import (
    FakeRegistry,
    MultiRegistry,
    case_registry,
    dist_for,
    package_registry,
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
FOUR_RULES_DISPLAY_ORDER = [
    "DYNAMIC_EVAL_ADDED",
    "JS_CHILD_PROCESS_ADDED",
    "NPM_INSTALL_SCRIPT_ADDED",
    "ENV_ENUMERATION_ADDED",
]


class _FlakyClient:
    """Returns one 429 for the first tarball request, then delegates."""

    def __init__(self, inner: MultiRegistry) -> None:
        self.inner = inner
        self.failed = False
        self.requests: list[str] = []

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        self.requests.append(url)
        if not self.failed and url.endswith(".tgz"):
            self.failed = True
            return HttpResponse(status=429, headers={"Retry-After": "0"}, body=b"")
        return self.inner.get(url, user_agent=user_agent, timeout=timeout, max_bytes=max_bytes)


class _ExplodingClient:
    """Fails the test if ``--plan`` ever reaches the network."""

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        raise AssertionError(f"unexpected HTTP request during --plan: {url}")


def _setup(tmp_path: Path, *registries: FakeRegistry) -> tuple[MultiRegistry, Path, Path]:
    """One changed pair per registry, plus a removed and a new-only package."""
    client = MultiRegistry(list(registries))
    old_packages: dict[str, Any] = {
        node_modules(item.name): registry_entry(item, OLD) for item in registries
    }
    new_packages: dict[str, Any] = {
        node_modules(item.name): registry_entry(item, NEW) for item in registries
    }
    old_packages[node_modules("gone-pkg")] = registry_entry(registries[0], OLD)
    new_packages[node_modules("added-pkg")] = {
        "version": "2.0.0",
        "resolved": "git+https://github.com/owner/added-pkg.git",
        "hasInstallScript": True,
    }
    return (
        client,
        write_lockfile(tmp_path / "old.json", old_packages),
        write_lockfile(tmp_path / "new.json", new_packages),
    )


def _run(
    capsys: pytest.CaptureFixture[str],
    client: MultiRegistry | _FlakyClient | _ExplodingClient,
    old_lock: Path,
    new_lock: Path,
    *extra: str,
    config: Config | None = None,
    cache: bool = False,
) -> tuple[int, str, str]:
    args = ["lock", "--old", str(old_lock), "--new", str(new_lock), *extra]
    # Tests never touch the user cache unless they opt in with a tmp cache_dir.
    if not cache and "--no-cache" not in extra:
        args.append("--no-cache")
    code = cli.main(args, client=client, config=config)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _plan_inputs(tmp_path: Path) -> tuple[MultiRegistry, Path, Path]:
    """One changed pair, one removed, one new-only git package, one skipped entry."""
    registry = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(
        tmp_path / "old.json",
        {
            node_modules("installer-pkg"): registry_entry(registry, OLD),
            node_modules("gone-pkg"): registry_entry(registry, OLD),
            "junk-entry": {"version": "1.0.0"},
        },
    )
    new_lock = write_lockfile(
        tmp_path / "new.json",
        {
            node_modules("installer-pkg"): registry_entry(registry, NEW),
            node_modules("added-pkg"): {
                "version": "2.0.0",
                "resolved": "git+https://github.com/owner/added-pkg.git",
                "hasInstallScript": True,
            },
        },
    )
    return client, old_lock, new_lock


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


def test_a_benign_pair_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    client, old_lock, new_lock = _setup(
        tmp_path, case_registry(tmp_path, BENIGN, name="benign-pkg")
    )

    code, out, err = _run(capsys, client, old_lock, new_lock)

    assert code == 0
    assert err == ""
    assert "benign-pkg 1.0.0 -> 1.1.0" in out
    assert "score 0" in out
    assert "gone-pkg" in out
    assert "added-pkg 2.0.0 install-script" in out
    assert "GIT_SOURCE" in out
    assert DISCLAIMER in out


def test_an_installer_pair_exits_one_with_the_same_four_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _setup(
        tmp_path, case_registry(tmp_path, INSTALLER, name="installer-pkg")
    )

    code, out, _ = _run(capsys, client, old_lock, new_lock)

    assert code == 1
    assert "score 94" in out
    assert all(rule_id in out for rule_id in FOUR_RULES)


def test_json_mode_reports_every_section(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _setup(
        tmp_path, case_registry(tmp_path, INSTALLER, name="installer-pkg")
    )

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--json")
    payload = json.loads(out)

    assert code == 1
    assert payload["schema_version"] == 4
    assert payload["ecosystem"] == "npm"
    assert payload["old_lockfile"] == str(old_lock)
    assert payload["new_lockfile"] == str(new_lock)
    assert payload["lockfile_versions"] == {"old": 3, "new": 3}
    assert payload["measured"] is False
    assert payload["analysis_incomplete"] is False
    assert payload["disclaimer"] == DISCLAIMER
    assert payload["removed_packages"] == ["gone-pkg"]
    assert payload["new_packages"] == [
        {"name": "added-pkg", "version": "2.0.0", "has_install_script": True, "analysis": None}
    ]
    assert payload["new_packages_analysed"] is True
    assert payload["skipped"] == []
    assert payload["unanalysed"] == 1
    assert payload["unanalysed_packages"] == [
        {"name": "added-pkg", "old_version": None, "new_version": "2.0.0", "reason": "GIT_SOURCE"}
    ]
    assert len(payload["pairs"]) == 1
    pair = payload["pairs"][0]
    assert (pair["name"], pair["old_version"], pair["new_version"]) == (
        "installer-pkg",
        OLD,
        NEW,
    )
    assert pair["error"] is None
    assert pair["score"] == 94
    assert pair["digests"] == {"old": "integrity", "new": "integrity"}
    assert [item["rule_id"] for item in pair["findings"]] == FOUR_RULES_DISPLAY_ORDER
    assert pair["findings_omitted"] == 0
    assert set(pair["files"]) == {"added", "removed", "modified"}
    assert len(payload["rule_set_version"]) == 12


def test_a_failed_pair_exits_two_and_the_others_are_still_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    benign = case_registry(tmp_path, BENIGN, name="benign-pkg")
    broken = case_registry(tmp_path, INSTALLER, name="broken-pkg")
    broken.new_dist = dist_for(broken.new_tarball, corrupt=True)
    client, old_lock, new_lock = _setup(tmp_path, benign, broken)

    code, out, _ = _run(capsys, client, old_lock, new_lock)

    # Exit 2 wins over the 1 this run would otherwise return (SPEC §9.1(7)).
    assert code == 2
    assert "failed pairs:" in out
    assert "broken-pkg 1.0.0 -> 1.1.0 DIGEST_MISMATCH" in out
    assert "benign-pkg 1.0.0 -> 1.1.0" in out
    assert DISCLAIMER in out


def test_a_failed_pair_is_visible_in_json_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = case_registry(tmp_path, INSTALLER, name="broken-pkg")
    broken.new_dist = dist_for(broken.new_tarball, corrupt=True)
    client, old_lock, new_lock = _setup(tmp_path, broken)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--json")
    payload = json.loads(out)

    assert code == 2
    assert payload["analysis_incomplete"] is True
    assert payload["pairs"][0]["error"] == "DIGEST_MISMATCH"
    assert payload["pairs"][0]["findings"] == []
    assert payload["pairs"][0]["score"] == 0


def test_a_disagreeing_unpacked_size_fails_the_pair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = case_registry(tmp_path, BENIGN, name="broken-pkg")
    broken.new_dist["unpackedSize"] = 1  # real tree is far larger than one byte
    client, old_lock, new_lock = _setup(tmp_path, broken)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--json")
    payload = json.loads(out)

    assert code == 2
    assert payload["analysis_incomplete"] is True
    assert payload["pairs"][0]["error"] == "LIMITS_DISAGREE_WITH_REGISTRY"
    assert payload["pairs"][0]["findings"] == []


def test_ignore_removes_a_rule_from_findings_score_and_exit_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _setup(
        tmp_path, case_registry(tmp_path, INSTALLER, name="installer-pkg")
    )

    code, out, _ = _run(
        capsys,
        client,
        old_lock,
        new_lock,
        *(flag for rule_id in sorted(FOUR_RULES) for flag in ("--ignore", rule_id)),
    )
    payload_code, payload_out, _ = _run(
        capsys,
        client,
        old_lock,
        new_lock,
        "--json",
        *(flag for rule_id in sorted(FOUR_RULES) for flag in ("--ignore", rule_id)),
    )
    payload = json.loads(payload_out)

    assert code == 0
    # The rules are named by the ignored section, never reported as findings.
    assert "score 0" in out
    assert all(f"ignored: {rule_id} (1 findings)" in out for rule_id in FOUR_RULES)
    assert sorted(item["rule_id"] for item in payload["ignored_rules"]) == sorted(FOUR_RULES)
    assert payload["pairs"][0]["findings"] == []
    assert payload["pairs"][0]["score"] == 0
    assert payload_code == 0


def test_too_many_pairs_exits_two_instead_of_truncating(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _setup(
        tmp_path,
        case_registry(tmp_path, BENIGN, name="a-pkg"),
        case_registry(tmp_path, BENIGN, name="b-pkg"),
    )

    code, out, err = _run(capsys, client, old_lock, new_lock, "--max-pairs", "1", "--json")

    assert code == 2
    assert err.strip() == "TOO_MANY_PAIRS"
    assert json.loads(out) == {"error": "TOO_MANY_PAIRS", "measured": False}
    assert client.requests == []


def test_an_unsupported_lockfile_version_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(
        tmp_path / "old.json",
        {node_modules("benign-pkg"): registry_entry(registry, OLD)},
        lockfile_version=1,
    )
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("benign-pkg"): registry_entry(registry, NEW)}
    )

    code, _, err = _run(capsys, client, old_lock, new_lock)

    assert code == 2
    assert err.strip() == "LOCKFILE_UNSUPPORTED_VERSION (--old)"
    assert client.requests == []


def test_an_unknown_ignored_rule_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _setup(
        tmp_path, case_registry(tmp_path, BENIGN, name="benign-pkg")
    )

    code, _, err = _run(capsys, client, old_lock, new_lock, "--ignore", "NOT_A_RULE")

    assert code == 2
    assert err.strip() == "UNKNOWN_RULE_ID"


def test_identical_lockfiles_exit_zero_with_no_pairs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    packages = {node_modules("benign-pkg"): registry_entry(registry, OLD)}
    old_lock = write_lockfile(tmp_path / "old.json", packages)
    new_lock = write_lockfile(tmp_path / "new.json", dict(packages))

    code, out, _ = _run(capsys, client, old_lock, new_lock)

    assert code == 0
    assert "changed pairs: (none)" in out
    assert client.requests == []


def test_a_changed_pair_that_cannot_be_analysed_is_warned_about(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(
        tmp_path / "old.json",
        {node_modules("git-pkg"): registry_entry(registry, OLD)},
    )
    new_lock = write_lockfile(
        tmp_path / "new.json",
        {
            node_modules("git-pkg"): {
                "version": NEW,
                "resolved": "git+https://github.com/owner/git-pkg.git",
            },
            node_modules("new-only"): {
                "version": "1.0.0",
                "resolved": "git+https://github.com/owner/new-only.git",
            },
        },
    )

    code, out, _ = _run(capsys, client, old_lock, new_lock)
    json_code, json_out, _ = _run(capsys, client, old_lock, new_lock, "--json")
    payload = json.loads(json_out)

    # A missing analysis is not a clean result, but the default exit code is unchanged.
    assert code == 0
    assert json_code == 0
    assert client.requests == []
    assert "2 unanalysed" in out
    assert "WARNING" in out
    assert "unanalysed packages:" in out
    assert "git-pkg 1.0.0 -> 1.1.0 GIT_SOURCE" in out
    assert "new-only 1.0.0 GIT_SOURCE" in out
    assert payload["unanalysed"] == 2
    assert payload["unanalysed_packages"] == [
        {
            "name": "git-pkg",
            "old_version": OLD,
            "new_version": NEW,
            "reason": "GIT_SOURCE",
        },
        {
            "name": "new-only",
            "old_version": None,
            "new_version": "1.0.0",
            "reason": "GIT_SOURCE",
        },
    ]


def test_strict_skips_makes_an_unanalysed_pair_exit_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(
        tmp_path / "old.json",
        {node_modules("git-pkg"): registry_entry(registry, OLD)},
    )
    new_lock = write_lockfile(
        tmp_path / "new.json",
        {
            node_modules("git-pkg"): {
                "version": NEW,
                "resolved": "git+https://github.com/owner/git-pkg.git",
            }
        },
    )

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--strict-skips")

    assert code == 2
    assert "WARNING" in out
    assert DISCLAIMER in out


def test_the_tarball_cache_survives_a_second_run_and_no_cache_disables_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client, old_lock, new_lock = _setup(tmp_path, registry)
    cache_dir = tmp_path / "cache"
    config = Config.from_toml(
        f'[lock]\nrequest_delay_seconds = 0.0\ncache_dir = "{cache_dir.as_posix()}"\n'
    )
    tarballs = {registry.old_url, registry.new_url}

    first_code, _, _ = _run(capsys, client, old_lock, new_lock, config=config, cache=True)
    assert first_code == 0
    assert tarballs <= set(client.requests)

    client.requests.clear()
    second_code, _, _ = _run(capsys, client, old_lock, new_lock, config=config, cache=True)
    assert second_code == 0
    assert tarballs.isdisjoint(client.requests)

    client.requests.clear()
    _run(capsys, client, old_lock, new_lock, "--no-cache", config=config, cache=True)
    assert tarballs <= set(client.requests)


def test_a_429_is_retried_before_the_pair_is_analysed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    inner, old_lock, new_lock = _setup(tmp_path, registry)
    client = _FlakyClient(inner)
    config = Config.from_toml(
        "[lock]\nrequest_delay_seconds = 0.0\nretry_base_delay_seconds = 0.01\n"
    )

    code, out, err = _run(capsys, client, old_lock, new_lock, config=config)

    assert code == 0
    assert err == ""
    assert "benign-pkg 1.0.0 -> 1.1.0" in out
    assert "HTTP_ERROR" not in out


def test_duplicate_json_keys_exit_two_before_any_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock = tmp_path / "old.json"
    old_lock.write_text(
        '{"lockfileVersion": 3, "packages": {}, "packages": {}}',
        encoding="utf-8",
    )
    new_lock = write_lockfile(tmp_path / "new.json", {})

    code, _, err = _run(capsys, client, old_lock, new_lock)

    assert code == 2
    assert err.strip() == "LOCKFILE_DUPLICATE_KEY (--old)"
    assert client.requests == []


def _new_only_lockfiles(tmp_path: Path, registry: FakeRegistry) -> tuple[MultiRegistry, Path, Path]:
    """One brand-new package, no changed pairs: the no-baseline path."""
    client = MultiRegistry([registry])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules(registry.name): registry_entry(registry, NEW)}
    )
    return client, old_lock, new_lock


def test_a_new_package_with_an_install_script_exits_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client, old_lock, new_lock = _new_only_lockfiles(tmp_path, registry)

    code, out, _ = _run(capsys, client, old_lock, new_lock)
    json_code, json_out, _ = _run(capsys, client, old_lock, new_lock, "--json")
    payload = json.loads(json_out)

    assert code == 1
    assert json_code == 1
    assert "new packages (no baseline):" in out
    assert "noisier" in out
    assert "NPM_INSTALL_SCRIPT_ADDED" in out
    assert "changed pairs: (none)" in out
    analysis = payload["new_packages"][0]["analysis"]
    assert analysis["error"] is None
    assert "NPM_INSTALL_SCRIPT_ADDED" in {item["rule_id"] for item in analysis["findings"]}
    assert payload["pairs"] == []


def test_a_new_package_with_only_capability_findings_exits_zero_but_is_listed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = package_registry(
        tmp_path,
        "cap-pkg",
        old_version=OLD,
        new_version=NEW,
        old_files={"package.json": b'{"name":"cap-pkg","version":"1.0.0"}'},
        new_files={
            "package.json": b'{"name":"cap-pkg","version":"1.1.0"}',
            "index.js": b'const cp = require("child_process");\n',
        },
    )
    client, old_lock, new_lock = _new_only_lockfiles(tmp_path, registry)

    code, out, _ = _run(capsys, client, old_lock, new_lock)

    # Family 2 is shown but never changes the exit code for a package with no baseline.
    assert code == 0
    assert "JS_CHILD_PROCESS_ADDED" in out
    assert "cap-pkg 1.1.0" in out
    assert "new packages (no baseline):" in out


def test_a_new_package_with_an_unsupported_source_is_unanalysed_and_strict_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json",
        {
            node_modules("git-pkg"): {
                "version": "1.0.0",
                "resolved": "git+https://github.com/owner/git-pkg.git",
            }
        },
    )

    code, out, _ = _run(capsys, client, old_lock, new_lock)
    strict_code, _, _ = _run(capsys, client, old_lock, new_lock, "--strict-skips")

    assert code == 0
    assert strict_code == 2
    assert "WARNING" in out
    assert "git-pkg 1.0.0 GIT_SOURCE" in out
    assert client.requests == []


def test_no_new_lists_new_packages_without_analysing_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client, old_lock, new_lock = _new_only_lockfiles(tmp_path, registry)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--no-new")
    json_code, json_out, _ = _run(capsys, client, old_lock, new_lock, "--no-new", "--json")
    payload = json.loads(json_out)

    assert code == 0
    assert json_code == 0
    assert "new packages were NOT analysed (--no-new)" in out
    assert "installer-pkg 1.1.0" in out
    assert payload["new_packages_analysed"] is False
    assert payload["new_packages"][0]["analysis"] is None
    assert client.requests == []


def test_new_packages_count_toward_max_pairs_unless_no_new(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = case_registry(tmp_path, BENIGN, name="a-pkg")
    second = case_registry(tmp_path, BENIGN, name="b-pkg")
    client = MultiRegistry([first, second])
    old_lock = write_lockfile(tmp_path / "old.json", {})
    new_lock = write_lockfile(
        tmp_path / "new.json",
        {
            node_modules("a-pkg"): registry_entry(first, NEW),
            node_modules("b-pkg"): registry_entry(second, NEW),
        },
    )

    code, _, err = _run(capsys, client, old_lock, new_lock, "--max-pairs", "1")
    relaxed_code, _, _ = _run(capsys, client, old_lock, new_lock, "--max-pairs", "1", "--no-new")

    assert code == 2
    assert err.strip() == "TOO_MANY_PAIRS"
    assert relaxed_code == 0
    assert client.requests == []


def test_a_missing_old_lockfile_names_the_argument_not_the_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    new_lock = write_lockfile(tmp_path / "new.json", {})

    code, _, err = _run(capsys, client, tmp_path / "missing.json", new_lock)

    assert code == 2
    assert err.strip() == "LOCKFILE_NOT_FOUND (--old)"
    assert "missing.json" not in err
    assert client.requests == []


def test_a_missing_new_lockfile_names_the_argument_in_json_mode_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, BENIGN, name="benign-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(tmp_path / "old.json", {})

    code, out, err = _run(capsys, client, old_lock, tmp_path / "missing.json", "--json")

    assert code == 2
    assert err.strip() == "LOCKFILE_NOT_FOUND (--new)"
    assert json.loads(out) == {
        "error": "LOCKFILE_NOT_FOUND",
        "argument": "--new",
        "measured": False,
    }
    assert client.requests == []


def test_plan_lists_every_section_and_never_touches_the_network(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, old_lock, new_lock = _plan_inputs(tmp_path)

    code, out, err = _run(capsys, _ExplodingClient(), old_lock, new_lock, "--plan")

    assert code == 0
    assert err == ""
    assert "lock: package-lock v3 -> v3 (plan)" in out
    assert "changed pairs:" in out
    assert "installer-pkg 1.0.0 -> 1.1.0" in out
    assert "new packages:" in out
    assert "added-pkg 2.0.0 install-script" in out
    assert "removed packages:" in out
    assert "gone-pkg" in out
    assert "skipped:" in out
    assert "old junk-entry 1.0.0 UNSUPPORTED_PATH" in out
    assert "unanalysed packages:" in out
    assert "added-pkg 2.0.0 GIT_SOURCE" in out
    assert DISCLAIMER in out


def test_plan_json_reports_the_plan_sections(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _plan_inputs(tmp_path)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--plan", "--json")
    payload = json.loads(out)

    assert code == 0
    assert client.requests == []
    assert payload["lockfile_versions"] == {"old": 3, "new": 3}
    assert payload["changed_pairs"] == [
        {"name": "installer-pkg", "old_version": OLD, "new_version": NEW}
    ]
    assert payload["new_packages"] == [
        {"name": "added-pkg", "version": "2.0.0", "has_install_script": True}
    ]
    assert payload["removed_packages"] == ["gone-pkg"]
    assert payload["skipped"] == [
        {"side": "old", "name": "junk-entry", "version": "1.0.0", "reason": "UNSUPPORTED_PATH"}
    ]
    assert payload["unanalysed_packages"] == [
        {"name": "added-pkg", "old_version": None, "new_version": "2.0.0", "reason": "GIT_SOURCE"}
    ]


def test_plan_exits_two_with_unanalysed_entries_under_strict_skips(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _plan_inputs(tmp_path)

    code, _, _ = _run(capsys, client, old_lock, new_lock, "--plan", "--strict-skips")

    assert code == 2
    assert client.requests == []


def test_plan_still_names_the_failing_lockfile_argument(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, _, new_lock = _plan_inputs(tmp_path)

    code, _, err = _run(capsys, client, tmp_path / "missing.json", new_lock, "--plan")

    assert code == 2
    assert err.strip() == "LOCKFILE_NOT_FOUND (--old)"
    assert client.requests == []


def test_plan_over_max_pairs_exits_two_without_network(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _plan_inputs(tmp_path)

    code, _, err = _run(capsys, client, old_lock, new_lock, "--plan", "--max-pairs", "1")

    assert code == 2
    assert err.strip() == "TOO_MANY_PAIRS"
    assert client.requests == []


def test_plan_rejects_markdown_and_sarif(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _plan_inputs(tmp_path)

    code, out, err = _run(capsys, client, old_lock, new_lock, "--plan", "--markdown")

    assert code == 2
    assert err.strip() == "OUTPUT_OPTIONS_CONFLICT"
    assert "changed pairs:" not in out
    assert client.requests == []

    code2, _, err2 = _run(capsys, client, old_lock, new_lock, "--plan", "--sarif")

    assert code2 == 2
    assert err2.strip() == "OUTPUT_OPTIONS_CONFLICT"
    assert client.requests == []


def test_family_four_of_a_new_package_move_to_one_informational_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
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
    client, old_lock, new_lock = _new_only_lockfiles(tmp_path, registry)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--experimental")
    json_code, json_out, _ = _run(capsys, client, old_lock, new_lock, "--json", "--experimental")
    payload = json.loads(json_out)

    # The two family-4 findings are not meaningful as "changes" against an empty tree:
    # informational only, out of the findings list and out of the score.
    assert code == 0
    assert json_code == 0
    assert "metadata (informational): 1 dependency, repository present" in out
    assert "DEPENDENCY_ADDED" not in out
    assert "REPOSITORY_URL_CHANGED" not in out
    assert "meta-pkg 1.1.0" in out
    analysis = payload["new_packages"][0]["analysis"]
    assert analysis["findings"] == []
    assert analysis["score"] == 0
    assert analysis["informational"] == {
        "DEPENDENCY_ADDED": 1,
        "REPOSITORY_URL_CHANGED": 1,
    }


def test_a_changed_pair_still_shows_family_four_findings_in_its_score(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
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

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--experimental")
    json_code, json_out, _ = _run(capsys, client, old_lock, new_lock, "--json", "--experimental")
    payload = json.loads(json_out)

    # A LOW finding is below the default --fail-on threshold, but it is still shown and scored.
    assert code == 0
    assert json_code == 0
    assert "DEPENDENCY_ADDED" in out
    assert "metadata (informational)" not in out
    assert {item["rule_id"] for item in payload["pairs"][0]["findings"]} == {"DEPENDENCY_ADDED"}
    assert payload["pairs"][0]["score"] > 0


def test_lock_skips_experimental_families_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
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

    default_code, default_out, _ = _run(capsys, client, old_lock, new_lock)
    _, enabled_out, _ = _run(capsys, client, old_lock, new_lock, "--experimental")

    assert default_code == 0
    assert "DEPENDENCY_ADDED" not in default_out
    assert "DEPENDENCY_ADDED" in enabled_out


def _installer_pair(tmp_path: Path) -> tuple[MultiRegistry, Path, Path]:
    """One changed pair and nothing else."""
    registry = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(
        tmp_path / "old.json", {node_modules("installer-pkg"): registry_entry(registry, OLD)}
    )
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("installer-pkg"): registry_entry(registry, NEW)}
    )
    return client, old_lock, new_lock


def _write_config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "pkgwatch.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_config_ignore_without_a_reason_is_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)
    config = _write_config(tmp_path, '[lock]\nignored = [{rule = "DYNAMIC_EVAL_ADDED"}]\n')

    code, _, err = _run(capsys, client, old_lock, new_lock, "--config", str(config))

    assert code == 2
    assert err.strip() == "CONFIG_INVALID"
    assert client.requests == []


def test_a_missing_or_invalid_config_file_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)

    code, _, err = _run(capsys, client, old_lock, new_lock, "--config", str(tmp_path / "x.toml"))
    broken = _write_config(tmp_path, "this is [ not toml")
    invalid_code, _, invalid_err = _run(capsys, client, old_lock, new_lock, "--config", str(broken))

    assert code == 2
    assert err.strip() == "CONFIG_NOT_FOUND"
    assert invalid_code == 2
    assert invalid_err.strip() == "CONFIG_INVALID"
    assert client.requests == []


def test_config_ignores_with_reasons_are_shown_and_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)
    config = _write_config(
        tmp_path,
        '[lock]\nignored = [{rule = "DYNAMIC_EVAL_ADDED", reason = "accepted for now"}]\n',
    )

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--config", str(config))
    json_code, json_out, _ = _run(
        capsys, client, old_lock, new_lock, "--config", str(config), "--json"
    )
    payload = json.loads(json_out)

    assert code == 1
    assert json_code == 1
    assert "DYNAMIC_EVAL_ADDED" not in {item["rule_id"] for item in payload["pairs"][0]["findings"]}
    assert payload["pairs"][0]["score"] < 94
    assert "ignored: DYNAMIC_EVAL_ADDED (1 findings)" in out
    assert "accepted for now" in out
    assert payload["ignored_rules"] == [
        {"rule_id": "DYNAMIC_EVAL_ADDED", "findings": 1, "reason": "accepted for now"}
    ]


def test_config_fail_on_and_max_pairs_apply_unless_the_cli_overrides_them(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
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
    low_config = _write_config(tmp_path, '[lock]\nfail_on = "low"\n')

    # DEPENDENCY_ADDED is LOW: the default (medium) exits 0, the config's low exits 1.
    default_code, _, _ = _run(capsys, client, old_lock, new_lock, "--experimental")
    config_code, _, _ = _run(
        capsys, client, old_lock, new_lock, "--experimental", "--config", str(low_config)
    )
    assert default_code == 0
    assert config_code == 1

    plan_client, plan_old, plan_new = _plan_inputs(tmp_path)
    small_config = _write_config(tmp_path, "[lock]\nmax_pairs = 1\n")
    too_many_code, _, err = _run(
        capsys, plan_client, plan_old, plan_new, "--config", str(small_config)
    )
    relaxed_code, _, _ = _run(
        capsys, plan_client, plan_old, plan_new, "--config", str(small_config), "--max-pairs", "2"
    )

    # One changed pair + one analysed new package exceeds the config limit of 1;
    # the CLI --max-pairs wins over the config file.
    assert too_many_code == 2
    assert err.strip() == "TOO_MANY_PAIRS"
    assert relaxed_code == 1


def test_update_baseline_then_a_later_run_hides_the_acknowledged_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)
    baseline = tmp_path / "baseline.json"

    update_code, out, _ = _run(
        capsys,
        client,
        old_lock,
        new_lock,
        "--update-baseline",
        str(baseline),
        "--baseline-reason",
        "accepted for the audit",
    )

    # Writing the baseline does not change the run: findings still reported, exit 1.
    assert update_code == 1
    assert "DYNAMIC_EVAL_ADDED" in out
    document = json.loads(baseline.read_text(encoding="utf-8"))
    assert document["version"] == 1
    assert {item["rule_id"] for item in document["entries"]} == FOUR_RULES
    assert all(item["package"] == "installer-pkg" for item in document["entries"])
    assert all(item["reason"] == "accepted for the audit" for item in document["entries"])
    assert all(item["date"] == datetime.date.today().isoformat() for item in document["entries"])
    script_entry = next(
        item for item in document["entries"] if item["rule_id"] == "NPM_INSTALL_SCRIPT_ADDED"
    )
    assert script_entry["path"] == "package/package.json"

    applied_code, applied_out, _ = _run(
        capsys, client, old_lock, new_lock, "--baseline", str(baseline)
    )
    json_code, json_out, _ = _run(
        capsys, client, old_lock, new_lock, "--baseline", str(baseline), "--json"
    )
    payload = json.loads(json_out)

    # The three non-lifecycle entries are honoured; lifecycle (family 1) entries are not
    # honoured by default (SPEC §9.1 decision 18), so the install script stays visible.
    assert applied_code == 1
    assert json_code == 1
    assert "baselined: 3 findings" in applied_out
    assert payload["baselined"] == 3
    assert {item["rule_id"] for item in payload["pairs"][0]["findings"]} == {
        "NPM_INSTALL_SCRIPT_ADDED"
    }


def test_baseline_stops_matching_when_the_evidence_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = tmp_path / "baseline.json"

    def _registry(line: bytes) -> tuple[FakeRegistry, Path, Path]:
        registry = package_registry(
            tmp_path,
            "cp-pkg",
            old_version=OLD,
            new_version=NEW,
            old_files={
                "package.json": b'{"name":"cp-pkg","version":"1.0.0"}',
                "index.js": b"module.exports = 1;\n",
            },
            new_files={
                "package.json": b'{"name":"cp-pkg","version":"1.1.0"}',
                "index.js": line,
            },
        )
        client = MultiRegistry([registry])
        old_lock = write_lockfile(
            tmp_path / "old.json", {node_modules("cp-pkg"): registry_entry(registry, OLD)}
        )
        new_lock = write_lockfile(
            tmp_path / "new.json", {node_modules("cp-pkg"): registry_entry(registry, NEW)}
        )
        return client, old_lock, new_lock

    first = _registry(b'const cp = require("child_process");\n')
    update_code, _, _ = _run(
        capsys,
        first[0],
        first[1],
        first[2],
        "--update-baseline",
        str(baseline),
        "--baseline-reason",
        "reviewed",
    )
    assert update_code == 1
    assert len(json.loads(baseline.read_text(encoding="utf-8"))["entries"]) == 1

    # Same rule on the same path, different line: the finding reappears.
    second = _registry(b'const cp2 = require("child_process");\n')
    code, out, _ = _run(
        capsys,
        second[0],
        second[1],
        second[2],
        "--baseline",
        str(baseline),
    )

    assert code == 1
    assert "JS_CHILD_PROCESS_ADDED" in out
    assert "baselined:" not in out


def test_missing_and_malformed_baselines_exit_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)

    code, _, err = _run(
        capsys, client, old_lock, new_lock, "--baseline", str(tmp_path / "missing.json")
    )
    broken = tmp_path / "baseline.json"
    broken.write_text("[1, 2, 3]", encoding="utf-8")
    invalid_code, _, invalid_err = _run(
        capsys, client, old_lock, new_lock, "--baseline", str(broken)
    )

    assert code == 2
    assert err.strip() == "BASELINE_NOT_FOUND"
    assert invalid_code == 2
    assert invalid_err.strip() == "BASELINE_INVALID"
    assert client.requests == []


def test_update_baseline_requires_a_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)
    baseline = tmp_path / "baseline.json"

    code, _, err = _run(capsys, client, old_lock, new_lock, "--update-baseline", str(baseline))

    assert code == 2
    assert err.strip() == "BASELINE_REASON_REQUIRED"
    assert not baseline.exists()


def test_markdown_report_for_an_installer_pair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--markdown")

    assert code == 1
    assert "### pkgwatch lock report" in out
    assert "<details>" in out
    assert "<summary>" in out
    assert "changed pairs" in out
    assert "installer-pkg" in out
    assert all(rule_id in out for rule_id in FOUR_RULES)
    assert DISCLAIMER in out


def test_markdown_and_json_conflict(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)

    code, _, err = _run(capsys, client, old_lock, new_lock, "--markdown", "--json")

    assert code == 2
    assert err.strip() == "OUTPUT_OPTIONS_CONFLICT"
    assert client.requests == []


def _installer_baseline(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    """Run the installer pair once with --update-baseline and return the file."""
    registry = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client = MultiRegistry([registry])
    old_lock = write_lockfile(
        tmp_path / "old.json", {node_modules("installer-pkg"): registry_entry(registry, OLD)}
    )
    new_lock = write_lockfile(
        tmp_path / "new.json", {node_modules("installer-pkg"): registry_entry(registry, NEW)}
    )
    baseline = tmp_path / "baseline.json"
    code, _, _ = _run(
        capsys,
        client,
        old_lock,
        new_lock,
        "--update-baseline",
        str(baseline),
        "--baseline-reason",
        "accepted",
    )
    assert code == 1
    return baseline


def test_family_one_baseline_entries_are_not_honoured_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = _installer_baseline(tmp_path, capsys)
    client, old_lock, new_lock = _installer_pair(tmp_path)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--baseline", str(baseline))
    json_code, json_out, _ = _run(
        capsys, client, old_lock, new_lock, "--baseline", str(baseline), "--json"
    )
    payload = json.loads(json_out)

    # The three non-lifecycle entries are honoured; the install-script entry is not.
    assert code == 1
    assert json_code == 1
    assert "baselined: 3 findings" in out
    assert "NPM_INSTALL_SCRIPT_ADDED" in out
    assert payload["baselined"] == 3
    assert {item["rule_id"] for item in payload["pairs"][0]["findings"]} == {
        "NPM_INSTALL_SCRIPT_ADDED"
    }


def test_family_one_baseline_entries_are_honoured_with_the_opt_in(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    baseline = _installer_baseline(tmp_path, capsys)
    client, old_lock, new_lock = _installer_pair(tmp_path)

    code, out, _ = _run(
        capsys,
        client,
        old_lock,
        new_lock,
        "--baseline",
        str(baseline),
        "--baseline-allow-lifecycle",
    )

    assert code == 0
    assert "baselined: 4 findings" in out


def test_sarif_output_for_an_installer_pair(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _installer_pair(tmp_path)

    code, out, err = _run(capsys, client, old_lock, new_lock, "--sarif")
    document = json.loads(out)

    assert code == 1
    assert err == ""
    assert document["version"] == "2.1.0"
    assert document["$schema"] == cli.SARIF_SCHEMA_URI
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "pkgwatch"
    rule_ids = {item["ruleId"] for item in run["results"]}
    assert rule_ids == FOUR_RULES
    # Pair findings carry the package name (PairOut uses "name", not "package").
    assert all(item["properties"]["package"] == "installer-pkg" for item in run["results"])
    assert {item["id"] for item in run["tool"]["driver"]["rules"]} == FOUR_RULES
    assert run["properties"]["disclaimer"] == DISCLAIMER
    assert run["properties"]["measured"] is False


def test_sarif_includes_new_package_findings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = case_registry(tmp_path, INSTALLER, name="installer-pkg")
    client, old_lock, new_lock = _new_only_lockfiles(tmp_path, registry)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--sarif")
    document = json.loads(out)

    assert code == 1
    results = document["runs"][0]["results"]
    assert "NPM_INSTALL_SCRIPT_ADDED" in {item["ruleId"] for item in results}
    assert any(item["properties"]["package"] == "installer-pkg" for item in results)
    assert any(
        item["properties"].get("new_version") == NEW
        and item["properties"].get("old_version") is None
        for item in results
    )


def _sarif_note_ids(run: dict[str, object]) -> set[str]:
    invocations = run.get("invocations")
    assert isinstance(invocations, list), "SARIF run must carry an invocation"
    assert invocations, "SARIF run must carry an invocation"
    notifications = invocations[0].get("toolExecutionNotifications", [])
    return {str(item["descriptor"]["id"]) for item in notifications}


def test_sarif_lock_surfaces_unanalysed_packages(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client, old_lock, new_lock = _setup(
        tmp_path, case_registry(tmp_path, INSTALLER, name="installer-pkg")
    )

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--sarif")
    run = json.loads(out)["runs"][0]

    assert code == 1
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["properties"]["unanalysed"] == 1
    assert run["properties"]["analysis_incomplete"] is False
    assert "UNANALYSED_PACKAGES" in _sarif_note_ids(run)


def test_sarif_lock_marks_an_incomplete_analysis(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = case_registry(tmp_path, INSTALLER, name="broken-pkg")
    broken.new_dist = dist_for(broken.new_tarball, corrupt=True)
    client, old_lock, new_lock = _setup(tmp_path, broken)

    code, out, _ = _run(capsys, client, old_lock, new_lock, "--sarif")
    run = json.loads(out)["runs"][0]

    assert code == 2
    assert run["properties"]["analysis_incomplete"] is True
    note_ids = _sarif_note_ids(run)
    assert "ANALYSIS_INCOMPLETE" in note_ids
    assert "PACKAGE_ERRORS" in note_ids
