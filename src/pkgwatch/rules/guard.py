"""Failure policy (SPEC §4.4): a crash becomes an INFO finding, never a dead worker.

Exception messages and tracebacks are hostile input — a rule can be handed text straight
out of a package — so the record names the exception class and the rule, nothing else.
"""

from __future__ import annotations

from collections.abc import Callable

from pkgwatch.models import DiffContext, Finding, Severity
from pkgwatch.rules.registry import Rule

RULE_ENGINE_RULE_ID = "RULE_ENGINE_ERROR"
RULE_ENGINE_RULE_VERSION = 1


def engine_finding(
    ctx: DiffContext,
    *,
    evidence: str,
    path: str | None = None,
    details: dict[str, str | int | float | bool] | None = None,
) -> Finding:
    """A finding about the engine itself, carrying the release identity of its context."""
    return Finding(
        rule_id=RULE_ENGINE_RULE_ID,
        rule_version=RULE_ENGINE_RULE_VERSION,
        severity=Severity.INFO,
        path=path,
        evidence=evidence,
        ecosystem=ctx.ecosystem,
        package_name=ctx.package_name,
        old_version=ctx.old_version,
        new_version=ctx.new_version,
        details=details or {},
    )


def guard(
    ctx: DiffContext,
    rule: Rule,
    path: str | None,
    body: Callable[[], list[Finding]],
) -> list[Finding]:
    """Run ``body``, recording an INFO finding instead of letting the exception escape."""
    # One bad rule must not sink the release, and the message is package-controlled,
    # so the exception class name is all that gets recorded.
    try:
        return list(body())
    except Exception as exc:
        where = f" on {path}" if path is not None else " for the release"
        # A rule_id may be up to 96 chars but a Finding detail value caps at 64; bounding
        # here keeps the INFO record buildable so a long-id crash cannot escape the guard.
        return [
            engine_finding(
                ctx,
                path=path,
                evidence=f"rule {rule.rule_id} failed{where}",
                details={"exception": type(exc).__name__[:64], "rule_id": rule.rule_id[:64]},
            )
        ]
