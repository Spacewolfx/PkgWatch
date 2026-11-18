"""Every M3 invariant is re-checked from the file, not trusted from the writer."""

from __future__ import annotations

import json
from pathlib import Path

from pkgwatch.dataset.split import assign_split
from pkgwatch.dataset.validate import validate_dataset
from pkgwatch.features import FEATURE_NAMES
from pkgwatch.models import DatasetRecord, Label, LabelSource, Split
from tests.support.records import make_analysis_record


def _dataset_record(**overrides: object) -> dict:
    analysis = make_analysis_record(**overrides)
    features = dict.fromkeys(FEATURE_NAMES, 0)
    features["ecosystem"] = analysis.ecosystem.value
    features["file_dominant_role"] = "source"
    payload = analysis.model_dump(
        mode="json", exclude={"config_sha256", "experimental", "features"}
    )
    record = DatasetRecord(
        **payload,
        features=features,
        label=Label.UNKNOWN,
        label_source=LabelSource.NONE,
        label_confidence=0.0,
        split=assign_split(analysis.ecosystem.value, analysis.package_name),
        metric_eligible=False,
    )
    return json.loads(record.model_dump_json())


def _write(tmp_path: Path, *records: dict) -> Path:
    path = tmp_path / "dataset.jsonl"
    path.write_text(
        "\n".join(json.dumps(item, sort_keys=True) for item in records) + "\n", encoding="utf-8"
    )
    return path


def test_a_valid_file_passes(tmp_path: Path) -> None:
    report = validate_dataset(_write(tmp_path, _dataset_record()))
    assert report.ok is True
    assert report.record_count == 1
    assert report.issues == ()


def test_a_duplicate_pair_is_reported(tmp_path: Path) -> None:
    record = _dataset_record()
    report = validate_dataset(_write(tmp_path, record, record))
    assert report.ok is False
    assert {issue.code for issue in report.issues} == {"DATASET_DUPLICATE_PAIR"}


def test_a_mixed_toolchain_file_is_reported(tmp_path: Path) -> None:
    record = _dataset_record()
    other = _dataset_record()
    other["rule_set_version"] = record["rule_set_version"] + "-other"
    report = validate_dataset(_write(tmp_path, record, other))
    assert "DATASET_RECORD_INHOMOGENEOUS" in {issue.code for issue in report.issues}


def test_a_wrong_split_is_reported(tmp_path: Path) -> None:
    record = _dataset_record()
    record["split"] = Split.TEST.value if record["split"] != Split.TEST.value else Split.TRAIN.value
    report = validate_dataset(_write(tmp_path, record))
    assert "DATASET_SPLIT_MISMATCH" in {issue.code for issue in report.issues}


def test_a_sparse_feature_catalog_is_reported(tmp_path: Path) -> None:
    record = _dataset_record()
    del record["features"]["size_added_bytes"]
    report = validate_dataset(_write(tmp_path, record))
    assert "DATASET_FEATURE_INVALID" in {issue.code for issue in report.issues}


def test_an_eligible_unknown_is_reported(tmp_path: Path) -> None:
    record = _dataset_record()
    record["metric_eligible"] = True
    report = validate_dataset(_write(tmp_path, record))
    assert "DATASET_METRIC_INELIGIBLE" in {issue.code for issue in report.issues}


def test_an_incomplete_record_is_reported(tmp_path: Path) -> None:
    record = _dataset_record(analysis_incomplete=True)
    report = validate_dataset(_write(tmp_path, record))
    assert "DATASET_INCOMPLETE_RECORD" in {issue.code for issue in report.issues}
