"""Family 4 metadata rules: registry dependencies and the root-manifest repository field."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgwatch.diff.manifest import MANIFEST_INVALID_JSON, diff_root_manifests, manifest_parse_errors
from pkgwatch.models import ParseErrorKind, RuleFamily, Severity
from pkgwatch.rules import RULES
from pkgwatch.rules.family4_metadata import dependency_added, repository_url_changed
from tests.support.context import ctx_from_files

OLD = {"package/base.js": b"var base = 1;\n"}
GITHUB_REPOSITORY_BASES = (
    "owner/repo",
    "github:owner/repo",
    "git+https://github.com/owner/repo",
    "https://github.com/owner/repo",
    "git://github.com/owner/repo",
    "git+ssh://git@github.com/owner/repo",
)
GITHUB_REPOSITORY_VARIANTS = tuple(
    f"{base}{suffix}" for base in GITHUB_REPOSITORY_BASES for suffix in ("", ".git", "/", ".git/")
)


def _manifest(repository: str, version: str) -> bytes:
    return json.dumps({"name": "demo-pkg", "version": version, "repository": repository}).encode(
        "utf-8"
    )


def test_dependency_added_reports_new_names_in_sorted_order(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        OLD,
        OLD,
        metadata_before={"dependencies": {"a": "1.0.0"}},
        metadata_after={"dependencies": {"a": "1.0.0", "z": "2.0.0", "b": "3.0.0"}},
    )
    findings = dependency_added(ctx)

    assert [item.evidence for item in findings] == [
        "new dependency: b",
        "new dependency: z",
    ]
    assert all(item.severity is Severity.LOW for item in findings)
    assert all(item.path is None and item.line_start is None for item in findings)
    assert all(item.details["section"] == "dependencies" for item in findings)


def test_unchanged_and_removed_dependencies_are_ignored(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        OLD,
        OLD,
        metadata_before={"dependencies": {"a": "1.0.0", "gone": "1.0.0"}},
        metadata_after={"dependencies": {"a": "2.0.0"}},
    )
    assert dependency_added(ctx) == []


@pytest.mark.parametrize(
    ("metadata_before", "metadata_after", "expected"),
    [
        pytest.param({}, {"dependencies": {}}, [], id="absent-to-empty"),
        pytest.param(
            {},
            {"dependencies": {"new-dep": "1.0.0"}},
            ["new-dep"],
            id="absent-to-one",
        ),
        pytest.param({"dependencies": {"old-dep": "1.0.0"}}, {}, [], id="one-to-absent"),
        pytest.param(
            {"dependencies": None},
            {"dependencies": None},
            [],
            id="null-to-null",
        ),
    ],
)
def test_dependency_added_distinguishes_absent_null_and_empty_semantically(
    tmp_path: Path,
    metadata_before: dict[str, object],
    metadata_after: dict[str, object],
    expected: list[str],
) -> None:
    ctx = ctx_from_files(
        tmp_path,
        OLD,
        OLD,
        metadata_before=metadata_before,
        metadata_after=metadata_after,
    )
    findings = dependency_added(ctx)

    assert [item.details["dependency"] for item in findings] == expected


def test_a_hostile_dependencies_shape_is_ignored(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        OLD,
        OLD,
        metadata_before={"dependencies": ["not", "a", "map"]},
        metadata_after={"dependencies": {"new-dep": "1.0.0"}},
    )
    assert [item.details["dependency"] for item in dependency_added(ctx)] == ["new-dep"]


def test_repository_change_reads_the_root_manifest_of_both_trees(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": _manifest("https://example.invalid/old", "1.0.0")},
        {"package/package.json": _manifest("https://example.invalid/new", "1.1.0")},
    )
    findings = repository_url_changed(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "REPOSITORY_URL_CHANGED"
    assert findings[0].severity is Severity.MEDIUM
    assert findings[0].rule_version == 1
    assert findings[0].details == {"field": "repository", "change": "changed"}
    assert findings[0].evidence == (
        "repository field changed: https://example.invalid/old -> https://example.invalid/new"
    )


def test_an_unchanged_repository_is_ignored(tmp_path: Path) -> None:
    same = {"package/package.json": _manifest("https://example.invalid/same", "1.0.0")}
    assert repository_url_changed(ctx_from_files(tmp_path, same, same)) == []


@pytest.mark.parametrize("equivalent", GITHUB_REPOSITORY_VARIANTS)
def test_equivalent_github_repository_forms_are_ignored(tmp_path: Path, equivalent: str) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": _manifest("owner/repo", "1.0.0")},
        {"package/package.json": _manifest(equivalent, "1.1.0")},
    )
    assert repository_url_changed(ctx) == []


@pytest.mark.parametrize(
    ("old", "new"),
    [
        pytest.param("owner/repo", "other/repo", id="owner-changed"),
        pytest.param("owner/repo", "owner/other", id="repository-changed"),
        pytest.param(
            "https://github.com/owner/repo",
            "https://gitlab.com/owner/repo",
            id="host-changed",
        ),
    ],
)
def test_real_repository_changes_still_fire(tmp_path: Path, old: str, new: str) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": _manifest(old, "1.0.0")},
        {"package/package.json": _manifest(new, "1.1.0")},
    )
    findings = repository_url_changed(ctx)

    assert len(findings) == 1
    assert findings[0].evidence == f"repository field changed: {old} -> {new}"


@pytest.mark.parametrize(
    ("old", "new", "expected_count"),
    [
        pytest.param("custom:owner/repo", "custom:owner/repo", 0, id="same-unknown"),
        pytest.param("custom:owner/repo", "custom:owner/repo/", 1, id="raw-unknown-differs"),
        pytest.param("owner/repo/tree/main", "owner/repo/tree/other", 1, id="nested-path"),
    ],
)
def test_unknown_repository_formats_compare_as_raw_strings(
    tmp_path: Path, old: str, new: str, expected_count: int
) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": _manifest(old, "1.0.0")},
        {"package/package.json": _manifest(new, "1.1.0")},
    )
    assert len(repository_url_changed(ctx)) == expected_count


def test_a_malformed_root_manifest_is_a_parse_problem_not_a_crash(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": _manifest("https://example.invalid/old", "1.0.0")},
        {"package/package.json": b"{not json\n"},
    )

    assert repository_url_changed(ctx) == []  # no crash, no invented finding
    changes = diff_root_manifests(ctx)
    assert ("new", MANIFEST_INVALID_JSON) in changes.problems
    errors = manifest_parse_errors(changes)
    assert [error.kind for error in errors] == [ParseErrorKind.MANIFEST]
    assert [error.detail for error in errors] == [MANIFEST_INVALID_JSON]


def test_family_four_ships_only_the_two_implemented_rules() -> None:
    family = [rule for rule in RULES if RuleFamily.METADATA in rule.families]
    assert [rule.rule_id for rule in family] == [
        "DEPENDENCY_ADDED",
        "REPOSITORY_URL_CHANGED",
    ]
    assert [rule.severity for rule in family] == [Severity.LOW, Severity.MEDIUM]
    assert all(rule.rule_version == 1 for rule in family)
    assert "MAINTAINER_ADDED" not in {rule.rule_id for rule in RULES}
