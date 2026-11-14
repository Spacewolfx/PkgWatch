"""Human labels are operator data: a malformed row rejects the whole file, never silently."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from pkgwatch.labeling.errors import LabelError
from pkgwatch.labeling.human import HUMAN_COLUMNS, load_human_labels
from pkgwatch.models import Label

HEADER = ",".join(HUMAN_COLUMNS)
ROW = "npm,demo-pkg,1.0.0,1.1.0,benign,halley,2026-11-14,1.0,reviewed the diff"


def _write(tmp_path: Path, *rows: str, name: str = "a.csv") -> Path:
    directory = tmp_path / "human"
    directory.mkdir(exist_ok=True)
    (directory / name).write_text("\n".join([HEADER, *rows]) + "\n", encoding="utf-8")
    return directory


def test_a_valid_row_becomes_a_human_label_without_the_note(tmp_path: Path) -> None:
    labels = load_human_labels(_write(tmp_path, ROW))
    assert len(labels) == 1
    assert labels[0].label is Label.BENIGN
    assert labels[0].provenance == "human:halley:2026-11-14"
    assert not hasattr(labels[0], "note")


def test_an_empty_confidence_defaults_to_one(tmp_path: Path) -> None:
    row = "npm,demo-pkg,1.0.0,1.1.0,benign,halley,2026-11-14,,"
    assert load_human_labels(_write(tmp_path, row))[0].confidence == 1.0


def test_a_malformed_row_rejects_the_whole_file(tmp_path: Path) -> None:
    with pytest.raises(LabelError) as excinfo:
        load_human_labels(_write(tmp_path, ROW, "npm,demo-pkg,1.0.0"))
    assert excinfo.value.code == "LABEL_CSV_INVALID"
    assert excinfo.value.row == 3


def test_an_unknown_label_value_is_a_value_error(tmp_path: Path) -> None:
    row = "npm,demo-pkg,1.0.0,1.1.0,probably-fine,halley,2026-11-14,1.0,"
    with pytest.raises(LabelError) as excinfo:
        load_human_labels(_write(tmp_path, row))
    assert excinfo.value.code == "LABEL_VALUE_INVALID"


def test_a_duplicate_identity_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(LabelError) as excinfo:
        load_human_labels(_write(tmp_path, ROW, ROW))
    assert excinfo.value.code == "HUMAN_LABEL_DUPLICATE"


def test_a_missing_directory_means_no_claims(tmp_path: Path) -> None:
    assert load_human_labels(tmp_path / "absent") == ()


def test_a_non_utf8_note_byte_rejects_the_whole_file(tmp_path: Path) -> None:
    # A latin-1 byte in a note cell must map to the stable code, not UnicodeDecodeError.
    directory = tmp_path / "human"
    directory.mkdir()
    row = "npm,demo-pkg,1.0.0,1.1.0,benign,halley,2026-11-14,1.0,caf\xe9"
    (directory / "a.csv").write_bytes((HEADER + "\n" + row + "\n").encode("latin-1"))
    with pytest.raises(LabelError) as excinfo:
        load_human_labels(directory)
    assert excinfo.value.code == "LABEL_CSV_INVALID"


def test_an_oversized_csv_field_rejects_the_whole_file(tmp_path: Path) -> None:
    # A single field beyond csv.field_size_limit must map to the stable code, not csv.Error.
    row = "npm,demo-pkg,1.0.0,1.1.0,benign,halley,2026-11-14,1.0," + "x" * (
        csv.field_size_limit() + 1
    )
    with pytest.raises(LabelError) as excinfo:
        load_human_labels(_write(tmp_path, row))
    assert excinfo.value.code == "LABEL_CSV_INVALID"
