"""Human labels: committed CSV, the highest-precedence source (SPEC §7.3).

The ``note`` column exists so a reviewer can record why. It is parsed for shape and then
dropped: reviewer prose never reaches a shipped dataset.
"""

from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path

from pkgwatch.labeling.errors import LabelError
from pkgwatch.models import Ecosystem, Label
from pkgwatch.version import UnsupportedVersion
from pkgwatch.version import parse as parse_version

HUMAN_COLUMNS = (
    "ecosystem",
    "package_name",
    "old_version",
    "new_version",
    "label",
    "reviewer",
    "reviewed_at",
    "confidence",
    "note",
)
_REVIEWER_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?$")


@dataclass(frozen=True)
class HumanLabel:
    ecosystem: Ecosystem
    package_name: str
    old_version: str
    new_version: str
    label: Label
    reviewer: str
    reviewed_at: str
    confidence: float
    provenance: str

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return (self.ecosystem.value, self.package_name, self.old_version, self.new_version)


def load_human_labels(directory: Path) -> tuple[HumanLabel, ...]:
    """Every ``*.csv`` in sorted filename order. A bad row rejects the whole file."""
    if not directory.is_dir():
        return ()
    labels: list[HumanLabel] = []
    seen: set[tuple[str, str, str, str]] = set()
    for path in sorted(directory.glob("*.csv")):
        for number, row in enumerate(_rows(path), start=2):
            label = _parse(row, number)
            if label.identity in seen:
                raise LabelError("HUMAN_LABEL_DUPLICATE", row=number)
            seen.add(label.identity)
            labels.append(label)
    return tuple(labels)


def _rows(path: Path) -> list[dict[str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise LabelError("LABEL_CSV_INVALID") from None
    try:
        # newline="" is the documented construction: ``str.splitlines()`` also splits on
        # \v, \f, \x1c-\x1e, \x85 and U+2028/9, which would cut a quoted note into extra
        # records before csv ever sees it.
        reader = csv.DictReader(io.StringIO(text, newline=""))
        header = tuple(reader.fieldnames or ())
        rows = list(reader)
    except csv.Error:
        raise LabelError("LABEL_CSV_INVALID") from None
    if header != HUMAN_COLUMNS:
        raise LabelError("LABEL_CSV_INVALID", row=1)
    for number, row in enumerate(rows, start=2):
        if None in row or any(value is None for value in row.values()):
            raise LabelError("LABEL_CSV_INVALID", row=number)
    return rows


def _parse(row: dict[str, str], number: int) -> HumanLabel:
    cells = {name: (row.get(name) or "").strip() for name in HUMAN_COLUMNS}
    for name in HUMAN_COLUMNS[:-2]:
        if not cells[name]:
            raise LabelError("LABEL_CSV_INVALID", row=number)
    if not _REVIEWER_RE.fullmatch(cells["reviewer"]):
        raise LabelError("LABEL_CSV_INVALID", row=number)
    if not _DATE_RE.fullmatch(cells["reviewed_at"]):
        raise LabelError("LABEL_CSV_INVALID", row=number)
    try:
        confidence = float(cells["confidence"]) if cells["confidence"] else 1.0
    except ValueError:
        raise LabelError("LABEL_CSV_INVALID", row=number) from None
    if not 0.0 <= confidence <= 1.0:
        raise LabelError("LABEL_VALUE_INVALID", row=number)
    try:
        ecosystem = Ecosystem(cells["ecosystem"])
        label = Label(cells["label"])
    except ValueError:
        raise LabelError("LABEL_VALUE_INVALID", row=number) from None
    if ecosystem is Ecosystem.CRATES:
        raise LabelError("LABEL_VALUE_INVALID", row=number)
    for version in (cells["old_version"], cells["new_version"]):
        try:
            parse_version(ecosystem, version)
        except UnsupportedVersion:
            raise LabelError("LABEL_VALUE_INVALID", row=number) from None
    if not cells["package_name"] or len(cells["package_name"]) > 214:
        raise LabelError("LABEL_VALUE_INVALID", row=number)
    return HumanLabel(
        ecosystem=ecosystem,
        package_name=cells["package_name"],
        old_version=cells["old_version"],
        new_version=cells["new_version"],
        label=label,
        reviewer=cells["reviewer"],
        reviewed_at=cells["reviewed_at"],
        confidence=confidence,
        provenance=f"human:{cells['reviewer']}:{cells['reviewed_at']}",
    )
