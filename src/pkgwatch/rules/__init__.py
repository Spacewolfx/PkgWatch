"""Rule families; every rule is a pure DiffContext -> list[Finding] function.

Importing this package is what registers rules, so the set is explicit and ordered:
families 1, 2, 3, 4 in that order. Registration order is emission order.
"""

from __future__ import annotations

from collections.abc import Iterable

from pkgwatch.models import Ecosystem, RuleFamily
from pkgwatch.rules import (  # noqa: F401 - importing a family module registers its rules
    family1_lifecycle,
    family2_capability,
    family3_obfuscation,
    family4_metadata,
)
from pkgwatch.rules.registry import DEFAULT, Rule, rule_set_version

RULES: tuple[Rule, ...] = DEFAULT.rules


def rules_for(ecosystem: Ecosystem) -> tuple[Rule, ...]:
    """The rules that may run for one ecosystem, in registration order."""
    return DEFAULT.select(ecosystem)


def families_by_rule_id() -> dict[str, frozenset[RuleFamily]]:
    """Family membership per rule id — the score engine's corroboration input (SPEC §5)."""
    return DEFAULT.families()


def explanations_for(rule_ids: Iterable[str]) -> dict[str, tuple[str, str]]:
    """Neutral ``--explain`` copy for the rules that fired, keyed by rule id."""
    wanted = set(rule_ids)
    return {
        rule.rule_id: (rule.why_it_matters, rule.common_benign_causes)
        for rule in RULES
        if rule.rule_id in wanted
    }


__all__ = [
    "RULES",
    "explanations_for",
    "families_by_rule_id",
    "rule_set_version",
    "rules_for",
]
