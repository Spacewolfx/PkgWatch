"""Label precedence: human > advisory_db > rule_derived > none."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from pkgwatch.labeling.advisory import AdvisoryLabel
from pkgwatch.labeling.human import HumanLabel
from pkgwatch.models import AnalysisRecord, Label, LabelSource

RULE_DERIVED_THRESHOLD = 40
RULE_DERIVED_CONFIDENCE = 0.3


@dataclass(frozen=True)
class LabelConflict:
    """One losing label claim, kept so the export can audit it."""

    identity: tuple[str, str, str, str]
    winner_source: str
    winner_label: str
    loser_source: str
    loser_label: str
    loser_provenance: str | None
    reason: str


@dataclass(frozen=True)
class LabelDecision:
    """The winning label claim and every claim it beat."""

    label: Label
    source: LabelSource
    confidence: float
    provenance: str | None
    metric_eligible: bool
    conflicts: tuple[LabelConflict, ...]


@dataclass(frozen=True)
class _Claim:
    source: LabelSource
    label: Label
    confidence: float
    provenance: str | None
    advisory: bool = False


def resolve_label(
    record: AnalysisRecord,
    human: Sequence[HumanLabel],
    advisory: Sequence[AdvisoryLabel],
) -> LabelDecision:
    """Resolve one record's label by precedence, with ``none`` as a fallback only.

    ``unknown`` is not a candidate: appending it would make every labelled record emit a
    spurious conflict. Holdout eligibility (rule_derived on val/test) is applied by the
    exporter, which knows the split.
    """
    identity = (
        record.ecosystem.value,
        record.package_name,
        record.old_version,
        record.new_version,
    )
    candidates = [
        _Claim(LabelSource.HUMAN, item.label, item.confidence, item.provenance)
        for item in human
        if item.identity == identity
    ]
    candidates.extend(
        _Claim(
            LabelSource.ADVISORY_DB,
            item.label,
            item.confidence,
            item.provenance,
            advisory=True,
        )
        for item in advisory
        if item.identity == identity
    )
    if record.rule_score > 0:
        label = Label.SUSPICIOUS if record.rule_score >= RULE_DERIVED_THRESHOLD else Label.BENIGN
        candidates.append(_Claim(LabelSource.RULE_DERIVED, label, RULE_DERIVED_CONFIDENCE, None))
    if not candidates:
        return LabelDecision(
            label=Label.UNKNOWN,
            source=LabelSource.NONE,
            confidence=0.0,
            provenance=None,
            metric_eligible=False,
            conflicts=(),
        )
    winner = candidates[0]
    first_advisory = next((index for index, claim in enumerate(candidates) if claim.advisory), None)
    conflicts = tuple(
        LabelConflict(
            identity=identity,
            winner_source=winner.source.value,
            winner_label=winner.label.value,
            loser_source=loser.source.value,
            loser_label=loser.label.value,
            loser_provenance=loser.provenance,
            reason=(
                "advisory_duplicate" if loser.advisory and index != first_advisory else "precedence"
            ),
        )
        for index, loser in enumerate(candidates[1:], start=1)
    )
    return LabelDecision(
        label=winner.label,
        source=winner.source,
        confidence=winner.confidence,
        provenance=winner.provenance,
        metric_eligible=winner.label is not Label.UNKNOWN,
        conflicts=conflicts,
    )
