"""Registry contract from SPEC §4.1: explicit, ordered, versioned, documented, fixture-backed."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

import pytest

from pkgwatch.models import Ecosystem, RuleFamily, Severity
from pkgwatch.rules import RULES
from pkgwatch.rules.registry import Registry, Rule
from pkgwatch.rules.runner import run_rules
from tests.support.fixtures import RULE_FIXTURES, rule_context

RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SHIPPED_FAMILIES = {
    RuleFamily.LIFECYCLE_SCRIPTS,
    RuleFamily.DANGEROUS_CAPABILITY,
    RuleFamily.OBFUSCATION,
    RuleFamily.METADATA,
}
INTENT_WORDS = ("malicious", "malware", "attacker", "attack", "steal", "evil")


def _fake(rule_id: str = "TEST_RULE", rule_version: int = 1) -> Rule:
    def _fn(ctx: object) -> list[object]:
        """Detects nothing. Ignores everything."""
        return []

    return Rule(
        rule_id=rule_id,
        rule_version=rule_version,
        severity=Severity.LOW,
        ecosystems=(Ecosystem.NPM,),
        families=(RuleFamily.METADATA,),
        fn=_fn,
    )


def test_registry_is_non_empty_and_made_of_rules() -> None:
    assert RULES
    assert all(isinstance(rule, Rule) for rule in RULES)


def test_rule_ids_are_stable_uppercase_tokens() -> None:
    for rule in RULES:
        assert RULE_ID_RE.match(rule.rule_id), rule.rule_id


def test_rule_ids_are_unique_per_version() -> None:
    keys = [(rule.rule_id, rule.rule_version) for rule in RULES]
    assert len(keys) == len(set(keys))


def test_every_rule_declares_severity_ecosystems_and_families() -> None:
    for rule in RULES:
        assert isinstance(rule.severity, Severity)
        assert rule.ecosystems
        assert set(rule.ecosystems) <= set(Ecosystem)
        assert rule.families
        assert set(rule.families) <= set(RuleFamily)


def test_v02_ships_exactly_families_one_through_four() -> None:
    for rule in RULES:
        assert set(rule.families) <= SHIPPED_FAMILIES, rule.rule_id
    assert {family for rule in RULES for family in rule.families} == SHIPPED_FAMILIES


def test_v02_rule_ids_severities_and_versions_follow_the_operator_decision() -> None:
    expected = {
        "BASE64_BLOB_PRESENT": Severity.LOW,
        "HIGH_ENTROPY_STRINGS": Severity.LOW,
        "HEX_ESCAPE_DENSITY": Severity.LOW,
        "DEPENDENCY_ADDED": Severity.LOW,
        "REPOSITORY_URL_CHANGED": Severity.MEDIUM,
    }
    by_id = {rule.rule_id: rule for rule in RULES}
    for rule_id, severity in expected.items():
        assert by_id[rule_id].severity is severity
        assert by_id[rule_id].rule_version == 1
    assert len(RULES) == 12
    assert "MAINTAINER_ADDED" not in by_id  # deferred, SPEC §4.5.1


def test_every_rule_carries_neutral_explain_copy() -> None:
    for rule in RULES:
        assert rule.why_it_matters.strip(), rule.rule_id
        assert rule.common_benign_causes.strip(), rule.rule_id
        copy = f"{rule.why_it_matters} {rule.common_benign_causes}".lower()
        assert not any(word in copy for word in INTENT_WORDS), rule.rule_id


def test_every_rule_documented_detects_and_ignores() -> None:
    for rule in RULES:
        doc = (rule.fn.__doc__ or "").lower()
        assert "detects" in doc, rule.rule_id
        assert "ignore" in doc, rule.rule_id


def test_every_rule_ships_positive_and_negative_fixtures() -> None:
    for rule in RULES:
        for polarity in ("positive", "negative"):
            case = RULE_FIXTURES / rule.rule_id / polarity
            assert case.is_dir(), f"{rule.rule_id} has no {polarity} fixture"
            files = [path for path in case.rglob("*") if path.is_file()]
            assert files, f"{rule.rule_id}/{polarity} fixture is empty"


@pytest.mark.parametrize("rule", list(RULES), ids=[rule.rule_id for rule in RULES])
def test_positive_fixture_makes_the_rule_fire(rule: Rule, tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, rule.rule_id, "positive")
    assert rule.rule_id in {
        finding.rule_id
        for finding in run_rules(ctx, experimental=True)
    }


@pytest.mark.parametrize("rule", list(RULES), ids=[rule.rule_id for rule in RULES])
def test_negative_fixture_keeps_the_rule_quiet(rule: Rule, tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, rule.rule_id, "negative")
    assert rule.rule_id not in {
        finding.rule_id
        for finding in run_rules(ctx, experimental=True)
    }


def test_public_selector_returns_only_matching_ecosystem() -> None:
    from pkgwatch.rules import rules_for

    assert rules_for(Ecosystem.NPM) == RULES
    assert rules_for(Ecosystem.PYPI) == ()
    assert rules_for(Ecosystem.CRATES) == ()


def test_rule_set_version_is_twelve_hex_and_changes_with_semantics() -> None:
    from pkgwatch.rules import rule_set_version

    version = rule_set_version()
    assert re.fullmatch(r"[0-9a-f]{12}", version)
    assert version == rule_set_version()
    assert version != rule_set_version([replace(RULES[0], rule_version=99), *RULES[1:]])


def test_rule_set_version_is_order_independent() -> None:
    from pkgwatch.rules import rule_set_version

    assert rule_set_version(list(RULES)) == rule_set_version(list(reversed(RULES)))


def test_families_by_rule_id_covers_every_rule() -> None:
    from pkgwatch.rules import families_by_rule_id

    families = families_by_rule_id()
    assert set(families) == {rule.rule_id for rule in RULES}
    assert families[RULES[0].rule_id] == frozenset(RULES[0].families)


def test_duplicate_registration_is_rejected() -> None:
    local = Registry()
    local.register(
        rule_id="TEST_DUPLICATE_RULE",
        rule_version=1,
        severity=Severity.LOW,
        ecosystems=(Ecosystem.NPM,),
        families=(RuleFamily.METADATA,),
    )(_fake().fn)

    with pytest.raises(ValueError, match="already registered"):
        local.register(
            rule_id="TEST_DUPLICATE_RULE",
            rule_version=1,
            severity=Severity.LOW,
            ecosystems=(Ecosystem.NPM,),
            families=(RuleFamily.METADATA,),
        )(_fake().fn)


def test_registration_validates_rule_id_shape() -> None:
    local = Registry()
    with pytest.raises(ValueError, match="rule_id"):
        local.register(
            rule_id="lowercase-rule",
            rule_version=1,
            severity=Severity.LOW,
            ecosystems=(Ecosystem.NPM,),
            families=(RuleFamily.METADATA,),
        )(_fake().fn)


def test_registration_requires_documented_rule() -> None:
    local = Registry()

    def _undocumented(ctx: object) -> list[object]:
        return []

    with pytest.raises(ValueError, match="docstring"):
        local.register(
            rule_id="TEST_UNDOCUMENTED_RULE",
            rule_version=1,
            severity=Severity.LOW,
            ecosystems=(Ecosystem.NPM,),
            families=(RuleFamily.METADATA,),
        )(_undocumented)
