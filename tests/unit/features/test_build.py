"""The feature catalog is derived from the diff alone: no file re-reads, no source text."""

from __future__ import annotations

from pathlib import Path

from pkgwatch.features.build import FEATURE_NAMES, build_features
from pkgwatch.models import FileRole, ScoreResult
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
