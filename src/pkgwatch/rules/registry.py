"""Rule registry (SPEC §4.1): explicit, ordered, versioned, documented, fixture-backed.

Discovery is a decorator into a module-level registry, not a filesystem scan, so
``rule_set_version`` is reproducible and an unimported rule cannot exist. Registration
order is emission order.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field

from pkgwatch.models import DiffContext, Ecosystem, Finding, RuleFamily, Severity

RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")

RuleFn = Callable[[DiffContext], list[Finding]]


@dataclass(frozen=True)
class Rule:
    """A rule and its identity. ``fn`` must be pure over a ``DiffContext``."""

    rule_id: str
    rule_version: int
    severity: Severity
    ecosystems: tuple[Ecosystem, ...]
    families: tuple[RuleFamily, ...]
    fn: RuleFn = field(compare=False)
    # Neutral, static --explain copy lives next to each rule definition (v0.2).
    why_it_matters: str = ""
    common_benign_causes: str = ""

    def __call__(self, ctx: DiffContext) -> list[Finding]:
        return self.fn(ctx)


class Registry:
    """Ordered collection of registered rules, validating the contract on the way in."""

    def __init__(self) -> None:
        self._rules: list[Rule] = []

    @property
    def rules(self) -> tuple[Rule, ...]:
        return tuple(self._rules)

    def add(self, rule: Rule) -> Rule:
        _validate(rule)
        if any(existing.rule_id == rule.rule_id for existing in self._rules):
            raise ValueError(f"rule_id {rule.rule_id!r} is already registered")
        self._rules.append(rule)
        return rule

    def register(
        self,
        *,
        rule_id: str,
        rule_version: int,
        severity: Severity | str,
        ecosystems: Sequence[Ecosystem | str],
        families: Sequence[RuleFamily | str],
        why_it_matters: str = "",
        common_benign_causes: str = "",
    ) -> Callable[[RuleFn], RuleFn]:
        """Decorator form of :meth:`add`, as written in SPEC §4.1."""

        def decorate(fn: RuleFn) -> RuleFn:
            if not (fn.__doc__ or "").strip():
                raise ValueError(f"rule {rule_id}: fn needs a docstring naming what it detects")
            self.add(
                Rule(
                    rule_id=rule_id,
                    rule_version=rule_version,
                    severity=Severity(severity),
                    ecosystems=tuple(Ecosystem(item) for item in ecosystems),
                    families=tuple(RuleFamily(item) for item in families),
                    fn=fn,
                    why_it_matters=why_it_matters,
                    common_benign_causes=common_benign_causes,
                )
            )
            return fn

        return decorate

    def select(self, ecosystem: Ecosystem) -> tuple[Rule, ...]:
        return tuple(rule for rule in self._rules if ecosystem in rule.ecosystems)

    def families(self) -> dict[str, frozenset[RuleFamily]]:
        return {rule.rule_id: frozenset(rule.families) for rule in self._rules}


def _validate(rule: Rule) -> None:
    if not RULE_ID_RE.match(rule.rule_id):
        raise ValueError(f"rule_id {rule.rule_id!r} must match ^[A-Z][A-Z0-9_]*$")
    if rule.rule_version < 1:
        raise ValueError(f"rule {rule.rule_id}: rule_version must be >= 1")
    if not rule.ecosystems:
        raise ValueError(f"rule {rule.rule_id}: at least one ecosystem is required")
    if not rule.families:
        raise ValueError(f"rule {rule.rule_id}: at least one family is required")


def rule_set_version(rules: Iterable[Rule] | None = None) -> str:
    """First 12 hex of SHA-256 over the sorted ``rule_id@rule_version`` list (SPEC §5)."""
    active = DEFAULT.rules if rules is None else tuple(rules)
    tokens = sorted(f"{rule.rule_id}@{rule.rule_version}" for rule in active)
    digest = hashlib.sha256("|".join(tokens).encode("utf-8")).hexdigest()
    return digest[:12]


DEFAULT = Registry()

register = DEFAULT.register
