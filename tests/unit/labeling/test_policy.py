"""Precedence is human > advisory_db > rule_derived > none, and losers stay auditable."""

from __future__ import annotations

from pkgwatch.labeling.advisory import AdvisoryLabel
from pkgwatch.labeling.human import HumanLabel
from pkgwatch.labeling.policy import resolve_label
from pkgwatch.models import Ecosystem, Label, LabelSource
from tests.support.records import make_analysis_record


def _human(label: Label = Label.BENIGN) -> HumanLabel:
    return HumanLabel(
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="1.1.0",
        label=label,
        reviewer="reviewer",
        reviewed_at="2026-11-14",
        confidence=1.0,
        provenance="human:reviewer:2026-11-14",
    )


def _advisory(
    label: Label = Label.MALICIOUS,
    *,
    advisory_id: str = "MAL-2026-1",
    filename: str = "MAL-2026-1.json",
) -> AdvisoryLabel:
    return AdvisoryLabel(
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="1.1.0",
        label=label,
        confidence=0.9,
        provenance=f"osv:{advisory_id}:abcdef012345",
        advisory_id=advisory_id,
        filename=filename,
    )


def test_no_claim_is_unknown_at_zero_confidence() -> None:
    decision = resolve_label(make_analysis_record(), (), ())
    assert decision.label is Label.UNKNOWN
    assert decision.source is LabelSource.NONE
    assert decision.confidence == 0.0
    assert decision.metric_eligible is False


def test_a_high_score_is_rule_derived_suspicious_at_exactly_zero_point_three() -> None:
    decision = resolve_label(make_analysis_record(rule_score=40), (), ())
    assert decision.label is Label.SUSPICIOUS
    assert decision.source is LabelSource.RULE_DERIVED
    assert decision.confidence == 0.3
    assert decision.metric_eligible is True


def test_a_low_score_is_rule_derived_benign() -> None:
    decision = resolve_label(make_analysis_record(rule_score=39), (), ())
    assert decision.label is Label.BENIGN


def test_human_beats_advisory_and_the_loser_is_a_conflict() -> None:
    decision = resolve_label(make_analysis_record(), (_human(),), (_advisory(),))
    assert decision.source is LabelSource.HUMAN
    assert decision.label is Label.BENIGN
    assert len(decision.conflicts) == 1
    assert decision.conflicts[0].loser_source == "advisory_db"
    assert decision.conflicts[0].reason == "precedence"


def test_advisory_beats_rule_derived() -> None:
    decision = resolve_label(make_analysis_record(rule_score=90), (), (_advisory(),))
    assert decision.source is LabelSource.ADVISORY_DB
    assert decision.label is Label.MALICIOUS
    assert decision.conflicts[0].loser_source == "rule_derived"


def test_a_second_advisory_for_one_identity_is_an_advisory_duplicate() -> None:
    # SPEC §5.2: the loser stays auditable under its own reason, not "precedence".
    second = _advisory(Label.BENIGN, advisory_id="MAL-2026-2", filename="MAL-2026-2.json")
    decision = resolve_label(make_analysis_record(), (), (_advisory(), second))
    assert decision.source is LabelSource.ADVISORY_DB
    assert decision.label is Label.MALICIOUS
    assert len(decision.conflicts) == 1
    assert decision.conflicts[0].reason == "advisory_duplicate"
    assert decision.conflicts[0].loser_provenance == "osv:MAL-2026-2:abcdef012345"


def test_a_human_winner_still_records_the_advisory_duplicates() -> None:
    second = _advisory(Label.BENIGN, advisory_id="MAL-2026-2", filename="MAL-2026-2.json")
    decision = resolve_label(make_analysis_record(), (_human(),), (_advisory(), second))
    assert decision.source is LabelSource.HUMAN
    assert [c.reason for c in decision.conflicts] == ["precedence", "advisory_duplicate"]


def test_a_label_for_another_pair_is_ignored() -> None:
    other = HumanLabel(
        ecosystem=Ecosystem.NPM,
        package_name="other-pkg",
        old_version="1.0.0",
        new_version="1.1.0",
        label=Label.MALICIOUS,
        reviewer="reviewer",
        reviewed_at="2026-11-14",
        confidence=1.0,
        provenance="human:reviewer:2026-11-14",
    )
    assert resolve_label(make_analysis_record(), (other,), ()).source is LabelSource.NONE
