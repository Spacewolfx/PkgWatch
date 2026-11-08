"""Deterministic score (SPEC §5, weights ``w1``).

The score is a pure function of findings plus the versioned weights. It never sees a
model, the clock, or registry state, and it is capped at 100.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pkgwatch.config import ScoringConfig
from pkgwatch.models import (
    Ecosystem,
    Finding,
    RuleFamily,
    ScoreResult,
    Severity,
)
from pkgwatch.score.engine import score


def _finding(
    rule_id: str,
    *,
    severity: Severity = Severity.HIGH,
    path: str = "package/index.js",
    line: int = 1,
    version: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=version,
        severity=severity,
        path=path,
        evidence=f"{rule_id} at {path}:{line}",
        line_start=line,
        line_end=line,
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="1.1.0",
    )


def _score(
    findings: Sequence[Finding],
    *,
    families: dict[str, frozenset[RuleFamily]] | None = None,
    config: ScoringConfig | None = None,
) -> ScoreResult:
    default = {
        finding.rule_id: frozenset({RuleFamily.DANGEROUS_CAPABILITY}) for finding in findings
    }
    return score(
        findings,
        scoring=config or ScoringConfig(),
        families=families or default,
        rule_set_version="0123456789ab",
    )


def test_no_findings_scores_zero() -> None:
    result = _score([])
    assert result.score == 0
    assert result.breakdown == ()
    assert result.boosts == ()
    assert result.contributing_findings == ()
    assert result.weights_version == "w1"
    assert result.rule_set_version == "0123456789ab"


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.INFO, 0),
        (Severity.LOW, 4),
        (Severity.MEDIUM, 10),
        (Severity.HIGH, 20),
        (Severity.CRITICAL, 35),
    ],
)
def test_single_finding_uses_its_severity_base(severity: Severity, expected: int) -> None:
    result = _score([_finding("ONE_RULE", severity=severity)])
    assert result.score == expected


def test_count_decay_within_a_rule_group() -> None:
    assert _score([_finding("R_RULE", line=1)]).score == 20
    assert _score([_finding("R_RULE", line=i) for i in (1, 2)]).score == 30
    assert _score([_finding("R_RULE", line=i) for i in (1, 2, 3)]).score == 35
    assert _score([_finding("R_RULE", line=i) for i in range(1, 9)]).score == 35


def test_a_rule_repeated_across_many_files_does_not_blow_up_the_score() -> None:
    findings = [_finding("R_RULE", path=f"package/file{i}.js") for i in range(400)]
    assert _score(findings).score == 35


def test_a_group_is_scored_at_its_worst_severity() -> None:
    findings = [
        _finding("R_RULE", severity=Severity.LOW, line=1),
        _finding("R_RULE", severity=Severity.HIGH, line=2),
    ]
    result = _score(findings)
    assert result.breakdown[0].base == 20
    assert result.score == 30  # the worst severity sets the base; two instances still decay


def test_two_high_rules_corroborate() -> None:
    result = _score([_finding("A_RULE"), _finding("B_RULE", line=2)])
    assert result.score == 50
    assert [boost.name for boost in result.boosts] == ["multi_capability"]
    assert result.boosts[0].points == 10


def test_lifecycle_plus_capability_boosts() -> None:
    families = {
        "NPM_INSTALL_SCRIPT_ADDED": frozenset({RuleFamily.LIFECYCLE_SCRIPTS}),
        "JS_CHILD_PROCESS_ADDED": frozenset({RuleFamily.DANGEROUS_CAPABILITY}),
    }
    result = _score(
        [_finding("NPM_INSTALL_SCRIPT_ADDED"), _finding("JS_CHILD_PROCESS_ADDED", line=2)],
        families=families,
    )
    assert [boost.name for boost in result.boosts] == [
        "multi_capability",
        "lifecycle_plus_capability",
    ]
    assert result.score == 20 + 20 + 10 + 20


def test_lifecycle_plus_three_obfuscation_rules_boosts() -> None:
    obfuscated = ["BASE64_BLOB_PRESENT", "HIGH_ENTROPY_STRINGS", "HEX_ESCAPE_DENSITY"]
    families = {
        "NPM_INSTALL_SCRIPT_ADDED": frozenset({RuleFamily.LIFECYCLE_SCRIPTS}),
        **{name: frozenset({RuleFamily.OBFUSCATION}) for name in obfuscated},
    }
    findings = [_finding("NPM_INSTALL_SCRIPT_ADDED")] + [
        _finding(name, severity=Severity.LOW, line=index + 2)
        for index, name in enumerate(obfuscated)
    ]
    result = _score(findings, families=families)
    assert [boost.name for boost in result.boosts] == ["lifecycle_plus_obfuscation"]
    assert result.score == 20 + 12 + 15


def test_two_obfuscation_rules_are_not_enough_for_the_third_boost() -> None:
    families = {
        "NPM_INSTALL_SCRIPT_ADDED": frozenset({RuleFamily.LIFECYCLE_SCRIPTS}),
        "BASE64_BLOB_PRESENT": frozenset({RuleFamily.OBFUSCATION}),
        "HIGH_ENTROPY_STRINGS": frozenset({RuleFamily.OBFUSCATION}),
    }
    result = _score(
        [
            _finding("NPM_INSTALL_SCRIPT_ADDED"),
            _finding("BASE64_BLOB_PRESENT", severity=Severity.LOW, line=2),
            _finding("HIGH_ENTROPY_STRINGS", severity=Severity.LOW, line=3),
        ],
        families=families,
    )
    assert result.boosts == ()
    assert result.score == 28


def test_score_is_capped_at_one_hundred() -> None:
    findings = [
        _finding("A_RULE", severity=Severity.CRITICAL),
        _finding("B_RULE", severity=Severity.CRITICAL, line=2),
        _finding("C_RULE", severity=Severity.CRITICAL, line=3),
        _finding("D_RULE", severity=Severity.CRITICAL, line=4),
        _finding("E_RULE", severity=Severity.CRITICAL, line=5),
    ]
    result = _score(findings)
    assert result.score == 100
    assert (
        sum(contribution.subtotal for contribution in result.breakdown)
        + sum(boost.points for boost in result.boosts)
        > 100
    )


def test_breakdown_reports_the_arithmetic() -> None:
    findings = [_finding("A_RULE", line=1), _finding("A_RULE", line=2)]
    result = _score(findings)
    assert result.breakdown[0].rule_id == "A_RULE"
    assert result.breakdown[0].base == 20
    assert result.breakdown[0].count_weight == pytest.approx(1.5)
    assert result.breakdown[0].subtotal == pytest.approx(30.0)


def test_input_order_does_not_change_the_result() -> None:
    findings = [_finding("B_RULE", line=1), _finding("A_RULE", line=2)]
    forward = _score(findings)
    backward = _score(list(reversed(findings)))
    assert forward.model_dump() == backward.model_dump()


def test_info_findings_are_reported_but_never_alert() -> None:
    result = _score([_finding("RULE_ENGINE_ERROR", severity=Severity.INFO)])
    assert result.score == 0
    assert len(result.contributing_findings) == 1


def test_rule_version_splits_two_groups_of_the_same_rule_id() -> None:
    findings = [_finding("A_RULE", version=1), _finding("A_RULE", version=2, line=2)]
    result = _score(findings)
    assert len(result.breakdown) == 2
    assert {item.rule_version for item in result.breakdown} == {1, 2}


@st.composite
def _finding_sets(draw: st.DataObject) -> list[Finding]:
    count = draw(st.integers(min_value=0, max_value=8))
    pool = ["A_RULE", "B_RULE", "C_RULE", "NPM_INSTALL_SCRIPT_ADDED"]
    severities = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return [
        _finding(
            draw(st.sampled_from(pool)),
            severity=draw(st.sampled_from(severities)),
            path=f"package/f{index}.js",
            line=index + 1,
        )
        for index in range(count)
    ]


@given(findings=_finding_sets())
def test_adding_a_finding_never_lowers_the_score(findings: list[Finding]) -> None:
    families = {
        rule_id: frozenset(
            {
                RuleFamily.LIFECYCLE_SCRIPTS
                if rule_id.startswith("NPM")
                else RuleFamily.DANGEROUS_CAPABILITY
            }
        )
        for rule_id in {finding.rule_id for finding in findings}
    }
    base = score(
        findings,
        scoring=ScoringConfig(),
        families=families,
        rule_set_version="0123456789ab",
    )
    assert 0 <= base.score <= 100
    if len(findings) >= 8:
        return
    extra = [
        *findings,
        _finding("Z_RULE", severity=Severity.HIGH, path="package/z.js", line=9),
    ]
    grown = score(
        extra,
        scoring=ScoringConfig(),
        families={**families, "Z_RULE": frozenset({RuleFamily.DANGEROUS_CAPABILITY})},
        rule_set_version="0123456789ab",
    )
    assert grown.score >= base.score
