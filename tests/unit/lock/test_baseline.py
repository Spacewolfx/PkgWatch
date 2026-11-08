"""The baseline file format and the exact match rule (SPEC §9.1 decision 16).

A finding is hidden only when (package name, rule_id, path, SHA-256 of the evidence
text) matches an entry. The version is never part of the match, and changed evidence
makes the finding reappear.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pkgwatch.lock.baseline import (
    BASELINE_INVALID,
    BASELINE_NOT_FOUND,
    BaselineEntry,
    BaselineError,
    evidence_sha256,
    load_baseline,
    make_entries,
    write_baseline,
)
from pkgwatch.models import Ecosystem, Finding, Severity


def _entry() -> BaselineEntry:
    return BaselineEntry(
        package="demo-pkg",
        rule_id="DEPENDENCY_ADDED",
        path=None,
        evidence_sha256=evidence_sha256("new dependency: left-pad"),
        reason="accepted",
        date="2026-11-08",
    )


def _finding(evidence: str, *, package: str = "demo-pkg") -> Finding:
    return Finding(
        rule_id="DEPENDENCY_ADDED",
        rule_version=1,
        severity=Severity.LOW,
        path=None,
        evidence=evidence,
        line_start=None,
        ecosystem=Ecosystem.NPM,
        package_name=package,
        old_version="1.0.0",
        new_version="2.0.0",
    )


def test_evidence_sha256_is_the_hex_sha256_of_the_evidence_text() -> None:
    assert (
        evidence_sha256("new dependency: left-pad")
        == hashlib.sha256(b"new dependency: left-pad").hexdigest()
    )
    assert len(evidence_sha256("anything")) == 64


def test_the_match_rule_ignores_the_version_and_compares_the_other_fields() -> None:
    entry = _entry()

    assert entry.matches(
        package="demo-pkg",
        rule_id="DEPENDENCY_ADDED",
        path=None,
        evidence="new dependency: left-pad",
    )
    assert not entry.matches(
        package="other-pkg",
        rule_id="DEPENDENCY_ADDED",
        path=None,
        evidence="new dependency: left-pad",
    )
    assert not entry.matches(
        package="demo-pkg",
        rule_id="REPOSITORY_URL_CHANGED",
        path=None,
        evidence="new dependency: left-pad",
    )
    assert not entry.matches(
        package="demo-pkg",
        rule_id="DEPENDENCY_ADDED",
        path="index.js",
        evidence="new dependency: left-pad",
    )
    # Changed evidence reappears: the hash no longer matches.
    assert not entry.matches(
        package="demo-pkg",
        rule_id="DEPENDENCY_ADDED",
        path=None,
        evidence="new dependency: right-pad",
    )


def test_write_then_load_round_trips_the_entries(tmp_path: Path) -> None:
    entries = (
        _entry(),
        BaselineEntry(
            package="demo-pkg",
            rule_id="DYNAMIC_EVAL_ADDED",
            path="index.js",
            evidence_sha256=evidence_sha256("eval(code)"),
            reason="known pattern",
            date="2026-11-08",
        ),
    )
    path = tmp_path / "baseline.json"
    write_baseline(path, entries)

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == 1
    assert document["entries"][0]["package"] == "demo-pkg"
    assert document["entries"][0]["date"] == "2026-11-08"
    assert load_baseline(path) == entries


def test_make_entries_deduplicates_by_the_match_key() -> None:
    entries = make_entries(
        [
            _finding("new dependency: left-pad"),
            _finding("new dependency: left-pad"),
            _finding("new dependency: right-pad"),
        ],
        reason="reviewed",
        today="2026-11-08",
    )

    assert len(entries) == 2
    assert {item.reason for item in entries} == {"reviewed"}
    assert {item.date for item in entries} == {"2026-11-08"}


def test_load_a_missing_file_raises_a_stable_code(tmp_path: Path) -> None:
    with pytest.raises(BaselineError) as caught:
        load_baseline(tmp_path / "missing.json")

    assert caught.value.code == BASELINE_NOT_FOUND


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param("not json", id="invalid-json"),
        pytest.param("[1, 2]", id="root-is-not-an-object"),
        pytest.param('{"version": 2, "entries": []}', id="wrong-version"),
        pytest.param('{"version": 1, "entries": {}}', id="entries-is-not-a-list"),
        pytest.param(
            '{"version": 1, "entries": [{"package": "p", "rule_id": "R"}]}',
            id="entry-missing-fields",
        ),
        pytest.param(
            '{"version": 1, "entries": [{"package": "p", "rule_id": "R", "path": null,'
            ' "evidence_sha256": "x", "reason": "", "date": "2026-11-08"}]}',
            id="entry-with-an-empty-reason",
        ),
    ],
)
def test_load_rejects_malformed_files_with_a_stable_code(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(BaselineError) as caught:
        load_baseline(path)

    assert caught.value.code == BASELINE_INVALID
