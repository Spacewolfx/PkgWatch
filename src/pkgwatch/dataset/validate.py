"""Re-check every M3 invariant from the exported JSONL, not from the writer's word.

Only the JSONL is validated. The manifest is checked by :func:`export_dataset` when it is
written; a second checker for the same fields would be two places to keep in sync.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from pkgwatch.dataset.split import assign_split
from pkgwatch.features import FEATURE_NAMES
from pkgwatch.models import (
    FEATURE_VOCABULARY,
    SCHEMA_VERSION,
    DatasetRecord,
    Label,
    LabelSource,
    Split,
)
from pkgwatch.rules import RULES

_HOLDOUT = {Split.VAL.value, Split.TEST.value}
_KNOWN_RULES = {rule.rule_id: rule.rule_version for rule in RULES}


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    line: int
    # A stable token we computed; never a value read from the record.
    detail: str = ""


@dataclass(frozen=True)
class ValidationReport:
    ok: bool
    record_count: int
    issues: tuple[ValidationIssue, ...]


def validate_dataset(path: Path) -> ValidationReport:
    """Walk the file line by line and report every invariant that fails."""
    text = path.read_text(encoding="utf-8")
    issues: list[ValidationIssue] = []
    parsed: list[tuple[int, DatasetRecord]] = []

    for number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        record = _record(raw, number, issues)
        if record is None:
            continue
        parsed.append((number, record))
        _check_record(record, number, issues)

    _check_cross_record(parsed, issues)
    ordered = tuple(sorted(issues, key=lambda issue: (issue.line, issue.code)))
    return ValidationReport(
        ok=not ordered,
        record_count=len(parsed),
        issues=ordered,
    )


def _record(raw: str, number: int, issues: list[ValidationIssue]) -> DatasetRecord | None:
    try:
        payload: Any = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        issues.append(ValidationIssue("DATASET_RECORD_INVALID", number))
        return None
    if not isinstance(payload, dict):
        issues.append(ValidationIssue("DATASET_RECORD_INVALID", number))
        return None
    # The model itself rejects an eligible unknown/holdout record. Diagnose that case first
    # so the reader learns *which* invariant failed, then relax exactly that field so the
    # remaining invariants are still checked on the same line.
    weak = payload.get("label") == Label.UNKNOWN.value or (
        payload.get("label_source") == LabelSource.RULE_DERIVED.value
        and payload.get("split") in _HOLDOUT
    )
    if weak and payload.get("metric_eligible") is True:
        issues.append(ValidationIssue("DATASET_METRIC_INELIGIBLE", number))
        payload["metric_eligible"] = False
    try:
        return DatasetRecord.model_validate(payload)
    except (ValidationError, ValueError):
        issues.append(ValidationIssue("DATASET_RECORD_INVALID", number))
        return None


def _check_record(record: DatasetRecord, number: int, issues: list[ValidationIssue]) -> None:
    if record.schema_version != SCHEMA_VERSION:
        issues.append(ValidationIssue("DATASET_RECORD_INVALID", number, "schema_version"))

    for finding in record.findings:
        if _KNOWN_RULES.get(finding.rule_id) != finding.rule_version:
            issues.append(ValidationIssue("DATASET_RECORD_INVALID", number, "rule_version"))
            break

    if set(record.features) != FEATURE_NAMES:
        issues.append(ValidationIssue("DATASET_FEATURE_INVALID", number, "catalog"))
    else:
        for name, allowed in FEATURE_VOCABULARY.items():
            if record.features[name] not in allowed:
                issues.append(ValidationIssue("DATASET_FEATURE_INVALID", number, name))
                break

    if record.analysis_incomplete:
        issues.append(ValidationIssue("DATASET_INCOMPLETE_RECORD", number))

    weak = record.label is Label.UNKNOWN or (
        record.label_source is LabelSource.RULE_DERIVED and record.split in _HOLDOUT
    )
    if weak and record.metric_eligible:
        issues.append(ValidationIssue("DATASET_METRIC_INELIGIBLE", number))

    if assign_split(record.ecosystem.value, record.package_name) is not record.split:
        issues.append(ValidationIssue("DATASET_SPLIT_MISMATCH", number))


def _check_cross_record(
    parsed: list[tuple[int, DatasetRecord]], issues: list[ValidationIssue]
) -> None:
    seen: dict[tuple[str, str, str, str], int] = {}
    splits: dict[tuple[str, str], Split] = {}
    for number, record in parsed:
        identity = (
            record.ecosystem.value,
            record.package_name,
            record.old_version,
            record.new_version,
        )
        if identity in seen:
            issues.append(ValidationIssue("DATASET_DUPLICATE_PAIR", number))
        seen.setdefault(identity, number)

        scope = (record.ecosystem.value, record.package_name)
        if scope in splits and splits[scope] is not record.split:
            issues.append(ValidationIssue("DATASET_SPLIT_CONFLICT", number))
        splits.setdefault(scope, record.split)
