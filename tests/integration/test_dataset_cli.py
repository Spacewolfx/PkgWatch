"""The two dataset commands, end to end, on records written by the offline compare path."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgwatch import cli
from tests.support.npm_registry import NEW_VERSION, OLD_VERSION, make_registry

BENIGN = "npm_benign_bump"


def _record(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Path:
    registry = make_registry(tmp_path, BENIGN)
    records = tmp_path / "records"
    code = cli.main(
        [
            "compare",
            f"npm:{registry.name}@{OLD_VERSION}",
            f"npm:{registry.name}@{NEW_VERSION}",
            "--json",
            "--no-cache",
            "--record-dir",
            str(records),
        ],
        client=registry,
    )
    capsys.readouterr()
    assert code == 0
    return records


def test_export_then_validate_round_trips(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    records = _record(tmp_path, capsys)
    out = tmp_path / "dataset"
    code = cli.main(
        [
            "export-dataset",
            "--records",
            str(records),
            "--labels",
            str(tmp_path / "labels"),
            "--out",
            str(out),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0, captured.err
    summary = json.loads(captured.out)
    assert summary["schema_version"] == 1
    assert summary["record_count"] == 1
    path = Path(summary["directory"]) / "dataset.jsonl"
    assert path.is_file()

    code = cli.main(["validate-dataset", "--path", str(path), "--json"])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    validation = json.loads(captured.out)
    assert validation["ok"] is True
    assert validation["schema_version"] == 1


def test_export_with_no_records_is_a_stable_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    empty = tmp_path / "records"
    empty.mkdir()
    code = cli.main(
        [
            "export-dataset",
            "--records",
            str(empty),
            "--labels",
            str(tmp_path / "labels"),
            "--out",
            str(tmp_path / "dataset"),
            "--json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "EXPORT_NO_RECORDS" in captured.err
    assert not (tmp_path / "dataset").exists()


def test_validate_reports_a_broken_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "broken.jsonl"
    path.write_text("{not a record}\n", encoding="utf-8")
    code = cli.main(["validate-dataset", "--path", str(path), "--json"])
    captured = capsys.readouterr()
    # spec §6.4: invalid content is a data verdict (1), not a tool error (2).
    assert code == 1
    report = json.loads(captured.out)
    assert report["ok"] is False
    assert report["errors"][0]["code"] == "DATASET_RECORD_INVALID"
