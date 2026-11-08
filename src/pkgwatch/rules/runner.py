"""The rule runner (SPEC §4.4): fixed order, per-rule isolation, honest accounting.

Findings come out in registration order so a release re-analysed later yields the same
bytes. A rule that raises, or that returns a finding under someone else's ``rule_id``,
is replaced by an INFO record naming it; the run continues.
"""

from __future__ import annotations

from collections.abc import Iterable

from pkgwatch.models import DiffContext, Finding
from pkgwatch.rules.guard import RULE_ENGINE_RULE_ID, engine_finding, guard
from pkgwatch.rules.registry import DEFAULT, Registry, Rule


class RuleContractViolation(Exception):
    """A rule returned a finding that is not its own."""


def _checked(rule: Rule, ctx: DiffContext) -> list[Finding]:
    returned = list(rule.fn(ctx))
    for finding in returned:
        if finding.rule_id not in (rule.rule_id, RULE_ENGINE_RULE_ID):
            raise RuleContractViolation(
                f"{rule.rule_id} returned a finding labelled {finding.rule_id!r}"
            )
    return returned


def _run(rule: Rule, ctx: DiffContext) -> list[Finding]:
    def body() -> list[Finding]:
        return _checked(rule, ctx)

    return guard(ctx, rule, None, body)


def _view_errors(ctx: DiffContext) -> Iterable[Finding]:
    for error in ctx.parse_errors:
        yield engine_finding(
            ctx,
            path=error.path,
            evidence=f"{error.kind} view of {error.path} is missing; analysis is partial",
            details={"stage": "diff", "kind": str(error.kind), "reason": error.detail[:64]},
        )


def run_rules(ctx: DiffContext, *, registry: Registry | None = None) -> list[Finding]:
    """Run every rule registered for ``ctx.ecosystem`` and return the findings."""
    active = registry if registry is not None else DEFAULT
    findings = list(_view_errors(ctx))
    for rule in active.select(ctx.ecosystem):
        findings.extend(_run(rule, ctx))
    return findings


def analysis_incomplete(findings: Iterable[Finding]) -> bool:
    """True when the engine itself had to report, so a score is not trustworthy."""
    return any(finding.rule_id == RULE_ENGINE_RULE_ID for finding in findings)
