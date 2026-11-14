"""Export joins labels, assigns splits and pins the run in a manifest. Offline, always."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pkgwatch.dataset.errors import DatasetError
from pkgwatch.dataset.export import export_dataset
from pkgwatch.models import DatasetRecord
from tests.support.records import make_analysis_record

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def _records(tmp_path: Path, count: int = 1) -> Path:
    directory = tmp_path / "records"
    directory.mkdir(exist_ok=True)
    for index in range(count):
        record = make_analysis_record(package_name=f"pkg-{index}")
        name = f"{index:064x}.json"
        (directory / name).write_text(record.model_dump_json(), encoding="utf-8")
    return directory


def test_an_empty_directory_is_a_stable_error(tmp_path: Path) -> None:
    empty = tmp_path / "records"
    empty.mkdir()
    with pytest.raises(DatasetError) as excinfo:
        export_dataset(records=empty, labels=tmp_path / "labels", out=tmp_path / "out", now=NOW)
    assert excinfo.value.code == "EXPORT_NO_RECORDS"


def test_one_record_exports_a_validating_jsonl_and_a_manifest(tmp_path: Path) -> None:
    result = export_dataset(
        records=_records(tmp_path), labels=tmp_path / "labels", out=tmp_path / "out", now=NOW
    )
    assert result.record_count == 1
    lines = (result.directory / "dataset.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    record = DatasetRecord.model_validate(json.loads(lines[0]))
    assert record.label_source.value == "none"
    assert record.metric_eligible is False
    manifest = json.loads((result.directory / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["sqlite_user_version"] is None
    assert manifest["split_salt"] == "pkgwatch-split-v1"
    assert "run_id" not in manifest
    assert (result.directory / "label_conflicts.jsonl").exists()


def test_the_same_inputs_and_clock_produce_the_same_run_id(tmp_path: Path) -> None:
    first = export_dataset(
        records=_records(tmp_path), labels=tmp_path / "labels", out=tmp_path / "a", now=NOW
    )
    second = export_dataset(
        records=_records(tmp_path), labels=tmp_path / "labels", out=tmp_path / "b", now=NOW
    )
    assert first.run_id == second.run_id


def test_an_existing_run_directory_is_refused(tmp_path: Path) -> None:
    records = _records(tmp_path)
    out = tmp_path / "out"
    export_dataset(records=records, labels=tmp_path / "labels", out=out, now=NOW)
    with pytest.raises(DatasetError) as excinfo:
        export_dataset(records=records, labels=tmp_path / "labels", out=out, now=NOW)
    assert excinfo.value.code == "EXPORT_RUN_EXISTS"


def test_incomplete_records_are_counted_and_skipped(tmp_path: Path) -> None:
    directory = tmp_path / "records"
    directory.mkdir()
    record = make_analysis_record(analysis_incomplete=True)
    (directory / f"{0:064x}.json").write_text(record.model_dump_json(), encoding="utf-8")
    result = export_dataset(
        records=directory, labels=tmp_path / "labels", out=tmp_path / "out", now=NOW
    )
    assert result.record_count == 0
    assert result.skipped_incomplete == 1


def test_mixed_rule_set_versions_are_refused(tmp_path: Path) -> None:
    directory = tmp_path / "records"
    directory.mkdir()
    for index, version in enumerate(("abc123def456", "ffffffffffff")):
        record = make_analysis_record(rule_set_version=version)
        (directory / f"{index:064x}.json").write_text(record.model_dump_json(), encoding="utf-8")
    with pytest.raises(DatasetError) as excinfo:
        export_dataset(records=directory, labels=tmp_path / "labels", out=tmp_path / "out", now=NOW)
    assert excinfo.value.code == "DATASET_RECORD_INHOMOGENEOUS"
