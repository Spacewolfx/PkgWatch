"""One npm release pair through the whole M2 chain: sandbox -> diff -> rules -> score -> store.

These are the two pairs the milestone is judged on: a benign bump that must stay silent,
and a synthetic installer that must produce exactly the findings named in SPEC §4.5 and a
score a human can re-derive by hand. Everything here is defanged fixture text — no
package code is executed, imported or installed, and nothing reaches the live registry.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pkgwatch.config import ScoringConfig
from pkgwatch.models import (
    SCHEMA_VERSION,
    Ecosystem,
    Finding,
    ReleaseStatus,
    RunRecord,
    Severity,
    WatchEntry,
)
from pkgwatch.rules import RULES, families_by_rule_id, rule_set_version
from pkgwatch.rules.runner import RULE_ENGINE_RULE_ID, analysis_incomplete, run_rules
from pkgwatch.score.engine import score
from pkgwatch.store.db import TARGET_VERSION, connect, migrate
from pkgwatch.store.repo import Repository
from tests.support.fixtures import package_context
from tests.support.records import make_previous_release, make_release

T0 = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def _shape(finding: Finding) -> tuple[object, ...]:
    """Everything that identifies a finding, without the denormalised release columns."""
    return (
        finding.rule_id,
        finding.severity,
        finding.path,
        finding.line_start,
        finding.line_end,
        finding.evidence,
        tuple(sorted(finding.details.items())),
    )


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[Repository]:
    connection: sqlite3.Connection = connect(tmp_path / "pkgwatch.sqlite3")
    migrate(connection)
    yield Repository(connection)
    connection.close()


def test_benign_bump_stays_silent_and_scores_zero(tmp_path: Path) -> None:
    ctx = package_context(tmp_path, "npm_benign_bump")
    findings = run_rules(ctx)
    result = score(
        findings,
        scoring=ScoringConfig(),
        families=families_by_rule_id(),
        rule_set_version=rule_set_version(),
    )

    assert findings == []
    assert analysis_incomplete(findings) is False
    assert result.score == 0
    assert result.breakdown == ()
    assert result.boosts == ()
    assert ctx.views_incomplete is False


def test_synthetic_installer_produces_exactly_four_findings(tmp_path: Path) -> None:
    ctx = package_context(tmp_path, "npm_synthetic_installer")
    findings = run_rules(ctx)

    assert [finding.rule_id for finding in findings] == [
        "NPM_INSTALL_SCRIPT_ADDED",
        "JS_CHILD_PROCESS_ADDED",
        "DYNAMIC_EVAL_ADDED",
        "ENV_ENUMERATION_ADDED",
    ]
    assert [_shape(finding) for finding in findings] == [
        (
            "NPM_INSTALL_SCRIPT_ADDED",
            Severity.HIGH,
            "package/package.json",
            5,
            5,
            '"postinstall": "echo installed",',
            (("script", "postinstall"),),
        ),
        (
            "JS_CHILD_PROCESS_ADDED",
            Severity.HIGH,
            "package/index.js",
            1,
            1,
            'const cp = require("child_process");',
            (("old_tree_scan", "full"), ("pattern", "child_process_require")),
        ),
        (
            "DYNAMIC_EVAL_ADDED",
            Severity.HIGH,
            "package/lib/env.js",
            2,
            2,
            'var decode = eval("names");',
            (("old_tree_scan", "full"), ("pattern", "eval_call")),
        ),
        (
            "ENV_ENUMERATION_ADDED",
            Severity.LOW,
            "package/lib/env.js",
            1,
            1,
            "var names = Object.keys(process.env);",
            (("old_tree_scan", "full"), ("pattern", "enumerate_process_env")),
        ),
    ]
    assert all(finding.package_name == ctx.package_name for finding in findings)
    assert RULE_ENGINE_RULE_ID not in [finding.rule_id for finding in findings]


def test_synthetic_installer_scores_ninety_four(tmp_path: Path) -> None:
    ctx = package_context(tmp_path, "npm_synthetic_installer")
    findings = run_rules(ctx)
    result = score(
        findings,
        scoring=ScoringConfig(),
        families=families_by_rule_id(),
        rule_set_version=rule_set_version(),
    )

    # 20 + 20 + 20 + 4 = 64, +10 multi_capability, +20 lifecycle_plus_capability.
    assert [(item.rule_id, item.base, item.subtotal) for item in result.breakdown] == [
        ("DYNAMIC_EVAL_ADDED", 20, 20.0),
        ("ENV_ENUMERATION_ADDED", 4, 4.0),
        ("JS_CHILD_PROCESS_ADDED", 20, 20.0),
        ("NPM_INSTALL_SCRIPT_ADDED", 20, 20.0),
    ]
    assert [(boost.name, boost.points) for boost in result.boosts] == [
        ("multi_capability", 10),
        ("lifecycle_plus_capability", 20),
    ]
    assert result.score == 94
    assert result.weights_version == "w1"
    assert result.rule_set_version == rule_set_version()
    assert len(result.contributing_findings) == len(findings) == 4


def test_scored_installer_is_stored_and_read_back(tmp_path: Path, repo: Repository) -> None:
    ctx = package_context(tmp_path, "npm_synthetic_installer")
    findings = run_rules(ctx)
    result = score(
        findings,
        scoring=ScoringConfig(),
        families=families_by_rule_id(),
        rule_set_version=rule_set_version(),
    )

    repo.add_watch(WatchEntry(ecosystem=Ecosystem.NPM, package_name="demo-pkg", added_at=T0))
    repo.upsert_release(make_previous_release())
    repo.upsert_release(make_release())
    for status in (
        ReleaseStatus.FETCHED,
        ReleaseStatus.EXTRACTED,
        ReleaseStatus.DIFFED,
    ):
        repo.set_status(Ecosystem.NPM, "demo-pkg", "1.1.0", status)
    repo.set_status(Ecosystem.NPM, "demo-pkg", "1.1.0", ReleaseStatus.SCORED)
    repo.set_analysis_incomplete(Ecosystem.NPM, "demo-pkg", "1.1.0", analysis_incomplete(findings))
    repo.record_run(
        RunRecord(
            run_id="2026-11-05T120000Z-installer",
            started_at=T0,
            finished_at=None,
            manifest_path="runs/2026-11-05T120000Z-installer/manifest.json",
            manifest={
                "score": result.score,
                "findings": [finding.model_dump(mode="json") for finding in findings],
            },
            rule_set_version=result.rule_set_version,
            weights_version=result.weights_version,
            schema_version=SCHEMA_VERSION,
            sqlite_user_version=TARGET_VERSION,
        )
    )
    repo.finish_run("2026-11-05T120000Z-installer", finished_at=T0)

    stored = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert stored is not None
    assert stored.status is ReleaseStatus.SCORED
    assert stored.analysis_incomplete is False

    run = repo.get_run("2026-11-05T120000Z-installer")
    assert run is not None
    assert run.finished_at == T0
    assert run.manifest["score"] == 94
    assert [finding["rule_id"] for finding in run.manifest["findings"]] == [
        finding.rule_id for finding in findings
    ]
    assert repo.remove_watch(Ecosystem.NPM, "demo-pkg") is True


def test_the_registry_offers_twelve_rules_and_a_stable_set_version() -> None:
    assert [rule.rule_id for rule in RULES] == [
        "NPM_INSTALL_SCRIPT_ADDED",
        "NPM_SCRIPT_INJECTION_FROM_METADATA",
        "JS_CHILD_PROCESS_ADDED",
        "DYNAMIC_EVAL_ADDED",
        "NET_ACCESS_ADDED",
        "FS_WRITE_OUTSIDE_PACKAGE_ADDED",
        "ENV_ENUMERATION_ADDED",
        "BASE64_BLOB_PRESENT",
        "HIGH_ENTROPY_STRINGS",
        "HEX_ESCAPE_DENSITY",
        "DEPENDENCY_ADDED",
        "REPOSITORY_URL_CHANGED",
    ]
    assert len(rule_set_version()) == 12
