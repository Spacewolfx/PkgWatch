"""The deterministic score (SPEC §5, weights ``w1``).

A pure function of findings plus versioned weights plus family membership: no model, no
clock, no registry state, no stored history. Monotone — adding a finding never lowers it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from pkgwatch.config import ScoringConfig
from pkgwatch.models import (
    Finding,
    RuleFamily,
    ScoreBoost,
    ScoreContribution,
    ScoreResult,
    Severity,
)

SCORE_MAX = 100
# SPEC §5's numeric corroboration bar, evaluated against the active base weight.
_CAPABILITY_BASE_MIN = 20
_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _worst(members: Sequence[Finding]) -> Severity:
    return max((finding.severity for finding in members), key=lambda item: _SEVERITY_RANK[item])


def _base(severity: Severity, scoring: ScoringConfig) -> int:
    weights = {
        Severity.INFO: scoring.severity.info,
        Severity.LOW: scoring.severity.low,
        Severity.MEDIUM: scoring.severity.medium,
        Severity.HIGH: scoring.severity.high,
        Severity.CRITICAL: scoring.severity.critical,
    }
    return weights[severity]


def _count_weight(instances: int, scoring: ScoringConfig) -> float:
    weights = scoring.decay.instance_weights
    return min(sum(weights[:instances]), scoring.decay.max_multiplier)


def _boosts(
    groups: Mapping[str, Sequence[Finding]],
    families: Mapping[str, frozenset[RuleFamily]],
    scoring: ScoringConfig,
) -> list[ScoreBoost]:
    """Corroboration, not volume: each boost applies once, however many rules earn it.

    SPEC §5's "base >= 20" bar is evaluated against the active weight table, so a
    re-weighted severity can move a rule across it without editing this function.
    """
    rule_ids = set(groups)
    capability_rules = {
        rule_id
        for rule_id, members in groups.items()
        if _base(_worst(members), scoring) >= _CAPABILITY_BASE_MIN
    }

    def in_family(family: RuleFamily) -> set[str]:
        return {rule_id for rule_id in rule_ids if family in families.get(rule_id, frozenset())}

    lifecycle = in_family(RuleFamily.LIFECYCLE_SCRIPTS)
    capability = in_family(RuleFamily.DANGEROUS_CAPABILITY)
    obfuscation = in_family(RuleFamily.OBFUSCATION)

    corroboration = scoring.corroboration
    applied: list[ScoreBoost] = []
    if len(capability_rules) >= 2:
        applied.append(ScoreBoost(name="multi_capability", points=corroboration.multi_capability))
    if lifecycle and capability:
        applied.append(
            ScoreBoost(
                name="lifecycle_plus_capability", points=corroboration.lifecycle_plus_capability
            )
        )
    if lifecycle and len(obfuscation) >= 3:
        applied.append(
            ScoreBoost(
                name="lifecycle_plus_obfuscation", points=corroboration.lifecycle_plus_obfuscation
            )
        )
    return applied


def score(
    findings: Sequence[Finding],
    *,
    scoring: ScoringConfig,
    families: Mapping[str, frozenset[RuleFamily]],
    rule_set_version: str,
) -> ScoreResult:
    """Group by rule, decay by count, boost on corroboration, clamp to ``[0, 100]``."""
    # SPEC §5 groups by rule_id only; rule_version is reported, never a second group.
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.rule_id, []).append(finding)

    breakdown: list[ScoreContribution] = []
    subtotal_sum = 0.0
    for rule_id in sorted(groups):
        members = sorted(groups[rule_id], key=_order)
        base = _base(_worst(members), scoring)
        weight = _count_weight(len(members), scoring)
        contribution = base * weight
        subtotal_sum += contribution
        breakdown.append(
            ScoreContribution(
                rule_id=rule_id,
                rule_version=max(item.rule_version for item in members),
                base=base,
                count_weight=weight,
                subtotal=contribution,
            )
        )

    boosts = _boosts(groups, families, scoring)
    raw = subtotal_sum + sum(boost.points for boost in boosts)
    total = max(0, min(SCORE_MAX, round(raw)))

    contributing = tuple(
        finding for rule_id in sorted(groups) for finding in sorted(groups[rule_id], key=_order)
    )
    return ScoreResult(
        score=total,
        rule_set_version=rule_set_version,
        weights_version=scoring.weights_version,
        contributing_findings=contributing,
        breakdown=tuple(breakdown),
        boosts=tuple(boosts),
    )


def _order(finding: Finding) -> tuple[str, int, str]:
    """Within a rule group: file first, then line, then evidence for a package-level hit."""
    return (finding.path or "", finding.line_start or 0, finding.evidence)
