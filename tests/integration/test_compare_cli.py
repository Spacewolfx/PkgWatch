"""The v0.1 compare command, end to end, against an injected offline registry.

Every tarball here is built from the committed synthetic fixture trees and unpacked by
``pkgwatch.sandbox``. No live registry, no sockets, and no package content is ever run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgwatch import cli
from pkgwatch.cli import DISCLAIMER
from pkgwatch.config import Config, FetchConfig
from pkgwatch.models import RejectionCode, SandboxLimits
from tests.support.fixtures import PACKAGE_FIXTURES
from tests.support.npm_registry import (
    NEW_VERSION,
    OLD_VERSION,
    FakeRegistry,
    dist_for,
    make_registry,
    tarball_bytes,
    tarball_from_files,
)

BENIGN = "npm_benign_bump"
INSTALLER = "npm_synthetic_installer"
FOUR_RULES = [
    "NPM_INSTALL_SCRIPT_ADDED",
    "JS_CHILD_PROCESS_ADDED",
    "DYNAMIC_EVAL_ADDED",
    "ENV_ENUMERATION_ADDED",
]
# v0.2 displays findings grouped by severity (highest first), then rule_id, path, line.
FOUR_RULES_DISPLAY_ORDER = [
    "DYNAMIC_EVAL_ADDED",
    "JS_CHILD_PROCESS_ADDED",
    "NPM_INSTALL_SCRIPT_ADDED",
    "ENV_ENUMERATION_ADDED",
]


def _run(
    capsys: pytest.CaptureFixture[str],
    registry: FakeRegistry,
    *extra: str,
    config: Config | None = None,
) -> tuple[int, str, str]:
    code = cli.main(
        [
            "compare",
            f"npm:{registry.name}@{OLD_VERSION}",
            f"npm:{registry.name}@{NEW_VERSION}",
            *extra,
        ],
        client=registry,
        config=config or Config(),
    )
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _tree_bytes(case_name: str, side: str) -> int:
    root = PACKAGE_FIXTURES / case_name / side
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def test_benign_pair_exits_zero_with_versions_counts_score_and_disclaimer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    code, out, err = _run(capsys, registry)

    assert code == 0
    assert err == ""
    assert "package: demo-pkg" in out
    assert f"old version: {OLD_VERSION}" in out
    assert f"new version: {NEW_VERSION}" in out
    assert "files: added=" in out
    assert "findings: (none)" in out
    assert "score: 0" in out
    assert "boosts: (none)" in out
    assert "digests: old=integrity, new=integrity" in out
    assert DISCLAIMER in out
    assert [url.startswith("https://registry.npmjs.org/") for url in registry.requests]
    assert len(registry.requests) == 3


def test_installer_pair_in_text_mode_exits_one_with_score_94(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, INSTALLER)
    code, out, err = _run(capsys, registry)

    assert code == 1
    assert err == ""
    assert "score: 94" in out
    assert "NPM_INSTALL_SCRIPT_ADDED high package/package.json:5" in out
    assert "JS_CHILD_PROCESS_ADDED high package/index.js:1" in out
    assert "DYNAMIC_EVAL_ADDED high package/lib/env.js:2" in out
    assert "ENV_ENUMERATION_ADDED low package/lib/env.js:1" in out
    assert "multi_capability +10" in out
    assert "lifecycle_plus_capability +20" in out
    assert DISCLAIMER in out


def test_installer_pair_in_json_mode_has_the_same_four_findings_and_score_94(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, INSTALLER)
    code, out, err = _run(capsys, registry, "--json")
    payload = json.loads(out)

    assert code == 1
    assert err == ""
    assert {item["rule_id"] for item in payload["findings"]} == set(FOUR_RULES)
    assert [item["rule_id"] for item in payload["findings"]] == FOUR_RULES_DISPLAY_ORDER
    assert [
        (item["rule_id"], item["severity"], item["path"], item["line"], item["evidence"])
        for item in payload["findings"]
    ] == [
        (
            "DYNAMIC_EVAL_ADDED",
            "high",
            "package/lib/env.js",
            2,
            'var decode = eval("names");',
        ),
        (
            "JS_CHILD_PROCESS_ADDED",
            "high",
            "package/index.js",
            1,
            'const cp = require("child_process");',
        ),
        (
            "NPM_INSTALL_SCRIPT_ADDED",
            "high",
            "package/package.json",
            5,
            '"postinstall": "echo installed",',
        ),
        (
            "ENV_ENUMERATION_ADDED",
            "low",
            "package/lib/env.js",
            1,
            "var names = Object.keys(process.env);",
        ),
    ]
    assert payload["score"] == 94
    assert payload["measured"] is False
    assert payload["boosts"] == [
        {"name": "multi_capability", "points": 10},
        {"name": "lifecycle_plus_capability", "points": 20},
    ]


def test_sarif_output_has_the_four_findings_with_levels(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, INSTALLER)
    code, out, err = _run(capsys, registry, "--sarif")
    document = json.loads(out)

    assert code == 1
    assert err == ""
    assert document["version"] == "2.1.0"
    assert document["$schema"] == cli.SARIF_SCHEMA_URI
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "pkgwatch"
    rule_ids = {item["ruleId"] for item in run["results"]}
    assert rule_ids == set(FOUR_RULES)
    levels = {item["ruleId"]: item["level"] for item in run["results"]}
    assert levels["NPM_INSTALL_SCRIPT_ADDED"] == "error"
    assert levels["ENV_ENUMERATION_ADDED"] == "note"
    assert levels["DYNAMIC_EVAL_ADDED"] == "error"
    assert run["properties"]["package"] == "demo-pkg"
    assert run["properties"]["measured"] is False
    assert all(
        item["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        for item in run["results"]
    )


def test_json_shape_is_stable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = make_registry(tmp_path, INSTALLER)
    code, out, _ = _run(capsys, registry, "--json")
    payload = json.loads(out)

    assert code == 1
    assert set(payload) == {
        "schema_version",
        "ecosystem",
        "package",
        "old_version",
        "new_version",
        "files",
        "findings",
        "score",
        "boosts",
        "digests",
        "changed_files",
        "changed_files_omitted",
        "package_json_changes",
        "registry_metadata_changes",
        "explanations",
        "ignored_rules",
        "rule_set_version",
        "measured",
        "warnings",
        "disclaimer",
    }
    assert payload["schema_version"] == 2
    assert payload["measured"] is False
    assert len(payload["rule_set_version"]) == 12
    assert set(payload["files"]) == {"added", "removed", "modified"}
    assert set(payload["package_json_changes"]) == {
        "sections",
        "repository",
        "parse_problems",
    }
    assert set(payload["package_json_changes"]["sections"]) == {
        "scripts",
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    }
    assert "gpt" not in payload["registry_metadata_changes"]["fields"]
    assert "maintainers" not in payload["registry_metadata_changes"]["fields"]
    assert payload["explanations"] == {}
    assert payload["ignored_rules"] == []
    assert all(
        set(item) == {"rule_id", "severity", "path", "line", "evidence", "details"}
        for item in payload["findings"]
    )
    assert all(set(item) == {"name", "points"} for item in payload["boosts"])
    assert payload["ecosystem"] == "npm"
    assert payload["package"] == "demo-pkg"
    assert payload["old_version"] == OLD_VERSION
    assert payload["new_version"] == NEW_VERSION
    assert payload["disclaimer"] == DISCLAIMER
    assert payload["digests"] == {"old": "integrity", "new": "integrity"}


def test_registry_metadata_fields_are_real_json_with_an_absent_sentinel(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    code, out, err = _run(capsys, registry, "--json")
    payload = json.loads(out)
    fields = payload["registry_metadata_changes"]["fields"]

    assert code == 0
    assert err == ""
    # Nested registry fields are JSON objects, never JSON-encoded strings.
    assert fields["scripts"]["old"] == {
        "state": "present",
        "value": {"test": "echo run tests"},
    }
    assert isinstance(fields["scripts"]["new"]["value"], dict)
    # A field the document omits is absent, and carries no value key at all.
    assert fields["dependencies"]["old"] == {"state": "absent"}
    assert fields["devDependencies"]["new"] == {"state": "absent"}
    assert fields["dist.size"]["old"] == {"state": "absent"}
    for sides in fields.values():
        for side in sides.values():
            assert side["state"] in {"absent", "null", "present"}
            assert ("value" in side) == (side["state"] == "present")


def test_empty_object_explicit_null_and_absent_are_three_different_states(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    doc = registry.document()
    doc["versions"][OLD_VERSION]["dependencies"] = {}
    doc["versions"][NEW_VERSION]["dependencies"] = None
    doc["versions"][OLD_VERSION]["dist"]["size"] = None
    doc["versions"][NEW_VERSION]["dist"]["size"] = 1234
    registry.doc_override = json.dumps(doc).encode("utf-8")

    code, out, _ = _run(capsys, registry, "--json")
    fields = json.loads(out)["registry_metadata_changes"]["fields"]

    assert code == 0
    # Present-but-empty stays empty; it is not folded into absent.
    assert fields["dependencies"]["old"] == {"state": "present", "value": {}}
    assert fields["dependencies"]["new"] == {"state": "null"}
    # The live is-number case: dist.size present but null on one side.
    assert fields["dist.size"]["old"] == {"state": "null"}
    assert fields["dist.size"]["new"] == {"state": "present", "value": 1234}


def test_fail_on_controls_exit_one(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = make_registry(tmp_path, INSTALLER)

    critical_code, _, _ = _run(capsys, registry, "--json", "--fail-on", "critical")
    high_code, _, _ = _run(capsys, registry, "--json", "--fail-on", "high")
    low_code, _, _ = _run(capsys, registry, "--json", "--fail-on", "low")

    assert critical_code == 0
    assert high_code == 1
    assert low_code == 1


def test_shasum_fallback_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.old_dist = dist_for(registry.old_tarball, method="shasum")
    registry.new_dist = dist_for(registry.new_tarball, method="shasum")

    code, out, err = _run(capsys, registry, "--json")

    assert code == 0
    assert err == ""
    assert json.loads(out)["digests"] == {"old": "shasum", "new": "shasum"}


def test_integrity_is_preferred_even_when_shasum_is_wrong(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.new_dist["shasum"] = "0" * 40

    code, out, err = _run(capsys, registry, "--json")

    assert code == 0
    assert err == ""
    assert json.loads(out)["digests"]["new"] == "integrity"


def test_digest_mismatch_exits_two_and_stops_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.old_dist = dist_for(registry.old_tarball, corrupt=True)

    code, out, err = _run(capsys, registry)

    assert code == 2
    assert err.strip() == "DIGEST_MISMATCH"
    assert "findings:" not in out
    assert "score:" not in out
    assert len(registry.requests) == 2  # document + old tarball only


def test_digest_mismatch_on_the_new_side_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.new_dist = dist_for(registry.new_tarball, corrupt=True)

    code, out, err = _run(capsys, registry, "--json")

    assert code == 2
    assert err.strip() == "DIGEST_MISMATCH"
    assert json.loads(out) == {"error": "DIGEST_MISMATCH", "measured": False}
    assert len(registry.requests) == 3


def test_oversized_tarball_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = make_registry(tmp_path, BENIGN)
    config = Config(fetch=FetchConfig(max_tarball_bytes=16))

    code, _, err = _run(capsys, registry, config=config)

    assert code == 2
    assert err.strip() == "SIZE_LIMIT_EXCEEDED"
    assert len(registry.requests) == 2  # document + first tarball, no extraction


def test_oversized_metadata_document_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    config = Config(fetch=FetchConfig(max_metadata_bytes=32))

    code, _, err = _run(capsys, registry, config=config)

    assert code == 2
    assert err.strip() == "SIZE_LIMIT_EXCEEDED"
    assert len(registry.requests) == 1


def test_cross_host_redirect_is_rejected_without_a_second_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.redirects[registry.new_url] = "https://evil.example.org/pkg.tgz"

    code, _, err = _run(capsys, registry)

    assert code == 2
    assert err.strip() == "REDIRECT_REJECTED"
    assert not any("evil.example" in url for url in registry.requests)


def test_same_host_redirect_is_followed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = make_registry(tmp_path, BENIGN)
    alias = "https://registry.npmjs.org/mirror/demo-pkg-1.1.0.tgz"
    registry.redirects[registry.new_url] = alias
    registry.aliases[alias] = registry.new_tarball

    code, out, err = _run(capsys, registry, "--json")

    assert code == 0
    assert err == ""
    assert json.loads(out)["score"] == 0
    assert alias in registry.requests


@pytest.mark.parametrize(
    ("first", "second", "code"),
    [
        ("pypi:demo-pkg@1.0.0", "npm:demo-pkg@1.1.0", "PACKAGE_MISMATCH"),
        ("npm:Demo-Pkg@1.0.0", "npm:Demo-Pkg@1.1.0", "INVALID_PACKAGE_NAME"),
        ("npm:demo-pkg@latest", "npm:demo-pkg@1.1.0", "INVALID_VERSION"),
        ("npm:demo-pkg@1.0.0", "npm:demo-pkg@^1.1.0", "INVALID_VERSION"),
        ("npm:demo-pkg@1.0.0", "npm:other-pkg@1.1.0", "PACKAGE_MISMATCH"),
        ("npm:@scope/pkg@1.0.0", "npm:@scope/other@1.1.0", "PACKAGE_MISMATCH"),
    ],
)
def test_invalid_specs_never_reach_the_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    first: str,
    second: str,
    code: str,
) -> None:
    registry = make_registry(tmp_path, BENIGN)

    exit_code = cli.main(["compare", first, second], client=registry, config=Config())
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.err.strip() == code
    assert registry.requests == []


def test_scoped_name_uses_the_spec_percent_encoded_document_url(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN, name="@scope/pkg")

    code, out, err = _run(capsys, registry, "--json")

    assert code == 0
    assert err == ""
    assert registry.requests[0] == "https://registry.npmjs.org/@scope%2Fpkg"
    assert json.loads(out)["package"] == "@scope/pkg"


def test_sandbox_rejection_exits_two_with_its_stable_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.set_new(tarball_bytes(tmp_path, BENIGN, "new", escape=True))

    code, out, err = _run(capsys, registry)

    assert code == 2
    assert err.strip() in {item.value for item in RejectionCode}
    assert "findings:" not in out
    assert "score:" not in out


def test_analysis_incomplete_exits_two_never_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A shared diff view budget forces one ParseError -> RULE_ENGINE_ERROR -> exit 2."""
    registry = make_registry(tmp_path, BENIGN)
    both_sides = _tree_bytes(BENIGN, "old") + _tree_bytes(BENIGN, "new")
    config = Config(sandbox=SandboxLimits(max_total_uncompressed_bytes=both_sides - 1))

    code, out, err = _run(capsys, registry, "--json", config=config)

    assert code == 2
    assert err.strip() == "ANALYSIS_INCOMPLETE"
    payload = json.loads(out)
    assert payload["error"] == "ANALYSIS_INCOMPLETE"
    assert payload["measured"] is False
    assert "budget" in payload["parse_problems"]


def test_error_output_never_leaks_package_controlled_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.doc_override = b"not json but HOSTILE-PACKAGE-TEXT"

    code, out, err = _run(capsys, registry)

    assert code == 2
    assert err.strip() == "REGISTRY_DOC_INVALID"
    assert "HOSTILE" not in out
    assert "HOSTILE" not in err
    assert DISCLAIMER in out


def test_user_agent_and_timeout_reach_every_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)

    code, _, _ = _run(capsys, registry)

    assert code == 0
    assert all(agent.startswith("pkgwatch/") for agent in registry.user_agents)
    assert all(timeout > 0 for timeout in registry.timeouts)
    assert len(registry.user_agents) == len(registry.requests) == 3


# --------------------------------------------------------------------------- v0.2


def _set_pair(
    registry: FakeRegistry,
    tmp_path: Path,
    old_files: dict[str, bytes],
    new_files: dict[str, bytes],
) -> None:
    old = tarball_from_files(tmp_path, "v02-old", old_files)
    new = tarball_from_files(tmp_path, "v02-new", new_files)
    registry.old_tarball = old
    registry.old_dist = dist_for(old)
    registry.new_tarball = new
    registry.new_dist = dist_for(new)


def test_changed_files_are_capped_at_50_and_verbose_shows_all(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    many = {f"f{i:03d}.js": f"var x = {i};\n".encode() for i in range(60)}
    registry.set_new(tarball_from_files(tmp_path, "many", many))

    code, out, err = _run(capsys, registry, "--json")
    payload = json.loads(out)
    assert code == 0
    # A total file-set replacement has modified==0, so the no-op guard warns (heuristic).
    assert "silent no-op" in err
    assert len(payload["changed_files"]) == 50
    assert payload["changed_files_omitted"] > 0

    code_v, out_v, _ = _run(capsys, registry, "--json", "--verbose")
    verbose_payload = json.loads(out_v)
    assert code_v == 0
    assert verbose_payload["changed_files_omitted"] == 0
    assert len(verbose_payload["changed_files"]) == 50 + payload["changed_files_omitted"]

    _, text_out, _ = _run(capsys, registry)
    assert "  ... " in text_out
    assert " more" in text_out
    _, verbose_text, _ = _run(capsys, registry, "--verbose")
    assert "  ... " not in verbose_text


def test_changed_files_report_status_and_old_new_sizes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    code, out, _ = _run(capsys, registry, "--json")
    payload = json.loads(out)
    counts = payload["files"]

    assert code == 0
    assert len(payload["changed_files"]) == sum(counts.values())
    assert all(item["status"] in {"A", "D", "M"} for item in payload["changed_files"])
    assert all(
        set(item) == {"status", "path", "size_old", "size_new"} for item in payload["changed_files"]
    )
    _, text_out, _ = _run(capsys, registry)
    assert "changed files:" in text_out
    assert "  M " in text_out or "  A " in text_out


def test_package_json_changes_report_added_removed_changed_and_repository(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    _set_pair(
        registry,
        tmp_path,
        {
            "package.json": (
                b'{"scripts":{"build":"echo b"},"dependencies":{"a":"1"},'
                b'"devDependencies":{"d":"1"},"repository":"https://example.invalid/old"}\n'
            )
        },
        {
            "package.json": (
                b'{"scripts":{"test":"echo t"},"dependencies":{"a":"2","b":"1"},'
                b'"devDependencies":{"d":"1"},"optionalDependencies":{"o":"1"},'
                b'"peerDependencies":{"p":"1"},"repository":"https://example.invalid/new"}\n'
            )
        },
    )

    code, out, _ = _run(capsys, registry, "--json", "--experimental")
    payload = json.loads(out)
    sections = payload["package_json_changes"]["sections"]

    assert code == 1  # REPOSITORY_URL_CHANGED is medium
    assert set(sections) == {
        "scripts",
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    }
    assert sections["scripts"] == {"added": ["test"], "removed": ["build"], "changed": []}
    assert sections["dependencies"] == {"added": ["b"], "removed": [], "changed": ["a"]}
    assert sections["optionalDependencies"]["added"] == ["o"]
    assert sections["peerDependencies"]["added"] == ["p"]
    assert payload["package_json_changes"]["repository"]["old"] == "https://example.invalid/old"
    assert payload["package_json_changes"]["repository"]["new"] == "https://example.invalid/new"
    assert payload["package_json_changes"]["parse_problems"] == []
    assert "REPOSITORY_URL_CHANGED" in {item["rule_id"] for item in payload["findings"]}

    _, text_out, _ = _run(capsys, registry)
    assert "package.json changes:" in text_out
    assert "scripts: added=test removed=build changed=-" in text_out
    assert "repository: https://example.invalid/old -> https://example.invalid/new" in text_out


def test_registry_metadata_changes_use_only_spec_v3_version_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    code, out, _ = _run(capsys, registry, "--json")
    payload = json.loads(out)
    fields = payload["registry_metadata_changes"]["fields"]

    assert code == 0
    assert "gpt" not in fields  # SPEC §3 TODO: looks like a typo, ignored
    assert "maintainers" not in fields  # package-level snapshot, not versions[v]
    assert fields["engines"] == {"old": {"state": "absent"}, "new": {"state": "absent"}}
    assert fields["dist.size"] == {"old": {"state": "absent"}, "new": {"state": "absent"}}
    assert fields["scripts"]["old"]["state"] == "present"

    _, text_out, _ = _run(capsys, registry)
    assert "registry metadata changes:" in text_out
    assert "  engines: (not available) -> (not available)" in text_out


def test_explain_prints_neutral_copy_for_rules_that_fired(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, INSTALLER)

    code, out, _ = _run(capsys, registry, "--explain")
    assert code == 1
    assert "Why it matters:" in out
    assert "Common benign causes:" in out
    section = out.split("explanations:", 1)[1].replace(DISCLAIMER, "")
    assert "malicious" not in section.lower()
    assert "attacker" not in section.lower()

    code_j, out_j, _ = _run(capsys, registry, "--explain", "--json")
    payload = json.loads(out_j)
    assert code_j == 1
    assert set(payload["explanations"]) == set(FOUR_RULES)
    assert all(copy["why_it_matters"] for copy in payload["explanations"].values())
    assert all(copy["common_benign_causes"] for copy in payload["explanations"].values())


def test_ignore_removes_a_rule_from_findings_score_and_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, INSTALLER)

    code, out, _ = _run(capsys, registry, "--ignore", "NPM_INSTALL_SCRIPT_ADDED", "--json")
    payload = json.loads(out)
    assert code == 1
    assert "NPM_INSTALL_SCRIPT_ADDED" not in {item["rule_id"] for item in payload["findings"]}
    assert payload["score"] < 94
    assert payload["ignored_rules"] == [{"rule_id": "NPM_INSTALL_SCRIPT_ADDED", "findings": 1}]

    _, text_out, _ = _run(capsys, registry, "--ignore", "NPM_INSTALL_SCRIPT_ADDED")
    assert "ignored: NPM_INSTALL_SCRIPT_ADDED (1 findings)" in text_out


def test_ignoring_every_finding_exits_zero_but_never_silently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, INSTALLER)
    args: list[str] = []
    for rule_id in FOUR_RULES:
        args.extend(["--ignore", rule_id])

    code, out, err = _run(capsys, registry, *args)

    assert code == 0
    assert err == ""
    assert "findings: (none)" in out
    assert "score: 0" in out
    assert all(f"ignored: {rule_id} (1 findings)" in out for rule_id in FOUR_RULES)


def test_ignore_with_zero_findings_is_still_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    code, out, _ = _run(capsys, registry, "--ignore", "NET_ACCESS_ADDED")
    assert code == 0
    assert "ignored: NET_ACCESS_ADDED (0 findings)" in out


def test_unknown_ignore_rule_is_an_error_before_any_network_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    code, _, err = _run(capsys, registry, "--ignore", "NO_SUCH_RULE")
    assert code == 2
    assert err.strip() == "UNKNOWN_RULE_ID"
    assert registry.requests == []


def test_malformed_root_manifest_is_a_parse_problem_and_exits_two(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = make_registry(tmp_path, BENIGN)
    registry.set_new(tarball_from_files(tmp_path, "bad-manifest", {"package.json": b"{not json\n"}))

    code, out, err = _run(capsys, registry, "--json")
    payload = json.loads(out)
    assert code == 2
    assert err.strip() == "ANALYSIS_INCOMPLETE"
    assert "manifest" in payload["parse_problems"]

    code_t, out_t, err_t = _run(capsys, registry)
    assert code_t == 2
    assert err_t.strip() == "ANALYSIS_INCOMPLETE"
    assert "parse problems: manifest" in out_t
    assert DISCLAIMER in out_t


def test_family_three_and_four_findings_surface_likely_minified(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    blob = (alpha * 10)[:520]
    registry = make_registry(tmp_path, BENIGN)
    registry.set_new(
        tarball_from_files(
            tmp_path,
            "obfuscated",
            {
                "dist/bundle.min.js": f'var d = "{blob}";\n'.encode(),
                "package.json": b'{"repository": "https://example.invalid/new"}\n',
            },
        )
    )
    document = registry.document()
    document["versions"][OLD_VERSION]["dependencies"] = {}
    document["versions"][NEW_VERSION]["dependencies"] = {"new-dep": "1.0.0"}
    registry.doc_override = json.dumps(document).encode("utf-8")

    code, out, _ = _run(capsys, registry, "--json", "--experimental")
    payload = json.loads(out)
    by_id = {item["rule_id"]: item for item in payload["findings"]}

    assert code == 1
    assert {
        "BASE64_BLOB_PRESENT",
        "HIGH_ENTROPY_STRINGS",
        "DEPENDENCY_ADDED",
        "REPOSITORY_URL_CHANGED",
    } <= set(by_id)
    blob_finding = by_id["BASE64_BLOB_PRESENT"]
    assert blob_finding["path"] == "package/dist/bundle.min.js"
    assert blob_finding["details"]["likely_minified"] is True
    assert blob not in blob_finding["evidence"]
    assert len(blob_finding["evidence"]) <= 200
    assert by_id["REPOSITORY_URL_CHANGED"]["severity"] == "medium"
    assert by_id["DEPENDENCY_ADDED"]["severity"] == "low"


def test_compare_skips_experimental_families_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    similar = make_registry(tmp_path, BENIGN)
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    similar.set_new(
        tarball_from_files(
            tmp_path, "obfuscated", {"dist/bundle.min.js": f'var d = "{alpha * 10}";\n'.encode()}
        )
    )
    document = similar.document()
    document["versions"][NEW_VERSION]["dependencies"] = {"new-dep": "1.0.0"}
    similar.doc_override = json.dumps(document).encode("utf-8")

    default_code, default_out, _ = _run(capsys, similar, "--json")
    enabled_code, enabled_out, _ = _run(capsys, similar, "--json", "--experimental")

    # The findings are LOW: below the default fail-on threshold, so both runs exit 0.
    assert default_code == 0
    assert "BASE64_BLOB_PRESENT" not in {
        item["rule_id"] for item in json.loads(default_out)["findings"]
    }
    assert "BASE64_BLOB_PRESENT" in {
        item["rule_id"] for item in json.loads(enabled_out)["findings"]
    }
    assert enabled_code == 0
