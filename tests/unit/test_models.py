from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from pkgwatch.models import (
    FEATURE_VOCABULARY,
    SCHEMA_VERSION,
    DatasetFinding,
    DatasetRecord,
    FileRole,
    Finding,
    Label,
    LabelSource,
    RejectionCode,
    Release,
    SandboxRejection,
    ScoreResult,
    Severity,
)
from tests.support.records import make_analysis_record


def make_finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "rule_id": "NPM_INSTALL_SCRIPT_ADDED",
        "rule_version": 1,
        "severity": "high",
        "path": "package.json",
        "evidence": "postinstall",
        "line_start": 1,
        "line_end": 1,
        "ecosystem": "npm",
        "package_name": "left-pad",
        "old_version": "1.0.0",
        "new_version": "1.0.1",
    }
    values.update(overrides)
    return Finding(**values)


def make_record(**overrides: Any) -> DatasetRecord:
    dataset_finding = DatasetFinding(
        rule_id="NPM_INSTALL_SCRIPT_ADDED", rule_version=1, severity=Severity.HIGH
    )
    values: dict[str, Any] = {
        "ecosystem": "npm",
        "package_name": "left-pad",
        "old_version": "1.0.0",
        "new_version": "1.0.1",
        "published_at": datetime(2024, 1, 1, tzinfo=UTC),
        "features": {
            "file_added_count": 3,
            "role_source_ratio": 0.75,
            "dominant_role": "source",
        },
        "findings": (dataset_finding,),
        "rule_score": 25,
        "label": "benign",
        "label_source": "human",
        "label_confidence": 1.0,
        "split": "train",
        "rule_set_version": "abc123",
        "weights_version": "w1",
        "artifact_sha256_old": "a" * 64,
        "artifact_sha256_new": "b" * 64,
    }
    values.update(overrides)
    return DatasetRecord(**values)


def test_evidence_is_capped_at_200_characters() -> None:
    finding = make_finding(evidence="A" * 500)
    assert len(finding.evidence) == 200
    assert finding.evidence.endswith("\u2026")


def test_finding_uid_is_stable_and_version_sensitive() -> None:
    first = make_finding()
    assert first.finding_uid == make_finding().finding_uid
    assert first.finding_uid != make_finding(rule_version=2).finding_uid


def test_finding_rejects_oversized_details() -> None:
    with pytest.raises(ValidationError):
        make_finding(details={"note": "x" * 100})


def test_release_requires_http_url() -> None:
    with pytest.raises(ValidationError):
        Release(
            ecosystem="npm",
            package_name="left-pad",
            version="1.0.0",
            published_at=datetime(2024, 1, 1, tzinfo=UTC),
            tarball_url="file:///etc/passwd",
            sha256="a" * 64,
            size=1,
            source_endpoint="https://registry.npmjs.org/left-pad",
        )


def test_score_is_bounded() -> None:
    finding = make_finding()
    with pytest.raises(ValidationError):
        ScoreResult(
            score=101,
            rule_set_version="abc",
            weights_version="w1",
            contributing_findings=(finding,),
            breakdown=(),
        )


def test_features_reject_raw_source_text() -> None:
    with pytest.raises(ValidationError, match="raw text"):
        make_record(features={"snippet": "import os; os.system('id')"})


def test_features_reject_unknown_names() -> None:
    with pytest.raises(ValidationError, match="invalid feature name"):
        make_record(features={"Bad-Name": 1})


def test_features_reject_non_finite_numbers() -> None:
    with pytest.raises(ValidationError, match="non-finite"):
        make_record(features={"entropy": float("nan")})


def test_rule_derived_is_never_metric_eligible_on_holdout() -> None:
    record = make_record(
        label="suspicious",
        label_source="rule_derived",
        label_confidence=0.3,
        split="test",
    )
    assert record.label_source is LabelSource.RULE_DERIVED
    assert record.metric_eligible is False

    with pytest.raises(ValidationError, match="metric-eligible"):
        make_record(
            label="suspicious",
            label_source="rule_derived",
            label_confidence=0.3,
            split="test",
            metric_eligible=True,
        )


def test_rule_derived_confidence_is_fixed() -> None:
    with pytest.raises(ValidationError, match=r"confidence 0\.3"):
        make_record(label="suspicious", label_source="rule_derived", label_confidence=0.9)


def test_advisory_labels_cannot_be_benign() -> None:
    with pytest.raises(ValidationError, match="malicious or unknown"):
        make_record(label="benign", label_source="advisory_db", label_confidence=0.9)


def test_sandbox_rejection_detail_is_capped_not_rejected() -> None:
    rejection = SandboxRejection(reason_code=RejectionCode.PATH_TOO_LONG, detail="x" * 300)
    assert len(rejection.detail) == 200
    assert rejection.detail.endswith("…")


def test_sandbox_rejection_offending_path_is_capped_and_sanitised() -> None:
    rejection = SandboxRejection(
        reason_code=RejectionCode.NAME_HAS_CONTROL_CHARS,
        detail="bad name",
        offending_path="p" * 300,
    )
    assert rejection.offending_path is not None
    assert len(rejection.offending_path) == 200
    assert rejection.offending_path.endswith("…")

    control = SandboxRejection(
        reason_code=RejectionCode.NAME_HAS_CONTROL_CHARS,
        detail="bad name",
        offending_path="a\x00b\x1fc",
    )
    assert control.offending_path == "a?b?c"


def test_a_record_with_no_label_claim_is_unknown() -> None:
    record = make_record(label="unknown", label_source="none", label_confidence=0.0)
    assert record.label_source is LabelSource.NONE
    assert record.label is Label.UNKNOWN


def test_no_claim_may_not_assert_a_label() -> None:
    with pytest.raises(ValidationError, match="no label claim"):
        make_record(label="benign", label_source="none", label_confidence=0.0)


def test_no_claim_may_not_carry_confidence() -> None:
    with pytest.raises(ValidationError, match=r"confidence 0.0"):
        make_record(label="unknown", label_source="none", label_confidence=0.5)


def test_unknown_labels_are_never_metric_eligible() -> None:
    for split in ("train", "val", "test"):
        record = make_record(
            label="unknown", label_source="none", label_confidence=0.0, split=split
        )
        assert record.metric_eligible is False, split


def test_an_explicit_eligible_unknown_is_rejected() -> None:
    with pytest.raises(ValidationError, match="metric-eligible"):
        make_record(
            label="unknown",
            label_source="none",
            label_confidence=0.0,
            split="train",
            metric_eligible=True,
        )


def test_a_categorical_outside_its_vocabulary_is_rejected() -> None:
    with pytest.raises(ValidationError, match="closed vocabulary"):
        make_record(features={"file_dominant_role": "payload"})


def test_the_vocabulary_covers_exactly_the_emitted_categoricals() -> None:
    assert set(FEATURE_VOCABULARY) == {"ecosystem", "file_dominant_role"}
    assert FEATURE_VOCABULARY["ecosystem"] == frozenset({"npm", "pypi"})
    assert FEATURE_VOCABULARY["file_dominant_role"] == frozenset(item.value for item in FileRole)


def test_analysis_record_carries_no_label_decision() -> None:
    record = make_analysis_record()
    fields = set(type(record).model_fields)
    assert not fields & {"label", "label_source", "label_confidence", "split", "metric_eligible"}
    assert record.schema_version == SCHEMA_VERSION
    assert record.experimental is False


def test_analysis_record_rejects_an_unknown_field() -> None:
    with pytest.raises(ValidationError):
        make_analysis_record(label="benign")


def test_analysis_record_shares_the_feature_boundary() -> None:
    with pytest.raises(ValidationError, match="closed vocabulary"):
        make_analysis_record(features={"file_dominant_role": "payload"})
