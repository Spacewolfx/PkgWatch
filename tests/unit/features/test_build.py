"""The catalog is derived from the diff and the findings: no file re-reads, no source text."""

from __future__ import annotations

from pathlib import Path

from pkgwatch.features.build import FEATURE_NAMES, build_features
from pkgwatch.models import Ecosystem, FileRole, Finding, ScoreResult, Severity
from pkgwatch.rules import rule_set_version
from tests.support.context import ctx_from_files


def _empty_result() -> ScoreResult:
    return ScoreResult(
        score=0,
        rule_set_version=rule_set_version(),
        weights_version="w1",
        contributing_findings=(),
        breakdown=(),
    )


def test_the_catalog_has_exactly_sixty_nine_names() -> None:
    assert len(FEATURE_NAMES) == 69


def test_size_and_file_features_describe_the_diff(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/index.js": b"module.exports = 1;\n"},
        {
            "package/index.js": b"module.exports = 2;\nconst x = 1;\n",
            "package/README.md": b"# demo\n",
        },
    )
    features = build_features(ctx, (), _empty_result())
    assert features["file_total_count"] == len(ctx.changes)
    assert features["file_added_doc_count"] == 1
    assert features["size_added_bytes"] > 0
    assert features["file_dominant_role"] in {item.value for item in FileRole}
    assert all(name in features for name in FEATURE_NAMES if name.startswith("size_"))


def test_an_empty_diff_still_emits_every_diff_feature(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, {"package/a.js": b"a\n"}, {"package/a.js": b"a\n"})
    features = build_features(ctx, (), _empty_result())
    # diff/ emits one `unchanged` change for an identical file, and it is text.
    assert features["file_total_count"] == 1
    assert features["file_added_source_count"] == 0
    assert features["file_text_ratio"] == 1.0
    assert features["size_net_delta_bytes"] == 0


def test_every_record_carries_the_full_closed_catalog(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, {"package/a.js": b"a\n"}, {"package/a.js": b"b\n"})
    features = build_features(ctx, (), _empty_result())
    assert set(features) == set(FEATURE_NAMES)
    assert list(features) == sorted(features)


def test_the_same_context_produces_identical_features(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, {"package/a.js": b"a\n"}, {"package/b.js": b"b\n"})
    assert build_features(ctx, (), _empty_result()) == build_features(ctx, (), _empty_result())


def test_capability_counts_merge_the_two_ecosystems(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, {"package/a.js": b"a\n"}, {"package/a.js": b"b\n"})
    findings = (
        Finding(
            rule_id="JS_CHILD_PROCESS_ADDED",
            rule_version=2,
            severity=Severity.HIGH,
            evidence="require('child_process')",
            ecosystem=Ecosystem.NPM,
            package_name="demo-pkg",
            old_version="1.0.0",
            new_version="1.1.0",
        ),
        Finding(
            rule_id="PYPI_SHELL_EXEC_ADDED",
            rule_version=2,
            severity=Severity.HIGH,
            evidence="os.system(",
            ecosystem=Ecosystem.PYPI,
            package_name="demo-pkg",
            old_version="1.0.0",
            new_version="1.1.0",
        ),
    )
    features = build_features(ctx, findings, _empty_result())
    assert features["capability_shell_exec_count"] == 2
    assert features["capability_total_count"] == 2
    assert features["score_finding_count"] == 2
    assert features["score_high_count"] == 2


def test_no_feature_carries_a_path_or_source_text(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path, {"package/a.js": b"a\n"}, {"package/a.js": b"require('child_process')\n"}
    )
    features = build_features(ctx, (), _empty_result())
    for name, value in features.items():
        if isinstance(value, str):
            assert "/" not in value, name
            assert "require" not in value, name
