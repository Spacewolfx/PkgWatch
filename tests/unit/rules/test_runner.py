"""Failure policy (SPEC §4.4): a crash becomes a record, never a dead worker."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pkgwatch.models import DiffContext, Ecosystem, Finding, RuleFamily, SandboxLimits, Severity
from pkgwatch.rules.guard import guard
from pkgwatch.rules.registry import Registry, Rule
from pkgwatch.rules.runner import RULE_ENGINE_RULE_ID, analysis_incomplete, run_rules
from tests.support.context import ctx_from_files
from tests.support.fixtures import rule_context

TWO_FILES = (
    {"package/a.js": b"var x = 1;\n"},
    {"package/a.js": b"var x = 2;\n", "package/bad.js": b"var y = 3;\n"},
)


def _rule(
    rule_id: str,
    fn: Callable[[DiffContext], list[Finding]],
    *,
    severity: Severity = Severity.MEDIUM,
    ecosystems: tuple[Ecosystem, ...] = (Ecosystem.NPM,),
    families: tuple[RuleFamily, ...] = (RuleFamily.DANGEROUS_CAPABILITY,),
) -> Rule:
    return Rule(
        rule_id=rule_id,
        rule_version=1,
        severity=severity,
        ecosystems=ecosystems,
        families=families,
        fn=fn,
    )


def _registry(*rules: Rule) -> Registry:
    local = Registry()
    for rule in rules:
        local.add(rule)
    return local


def _finding(context: DiffContext, rule_id: str, path: str | None, evidence: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=1,
        severity=Severity.LOW,
        path=path,
        evidence=evidence,
        ecosystem=context.ecosystem,
        package_name=context.package_name,
        old_version=context.old_version,
        new_version=context.new_version,
    )


def test_guard_returns_the_body_findings(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)
    rule = _rule("X_RULE", lambda inner: [])
    payload = _finding(context, "X_RULE", "package/a.js", "x")

    assert guard(context, rule, "package/a.js", lambda: [payload]) == [payload]


def test_guard_converts_an_exception_into_an_info_finding(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)
    rule = _rule("X_RULE", lambda inner: [])

    def _boom() -> list[Finding]:
        raise RuntimeError("hostile text /etc/shadow must not leak")

    findings = guard(context, rule, "package/a.js", _boom)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ENGINE_RULE_ID
    assert finding.severity is Severity.INFO
    assert finding.path == "package/a.js"
    assert finding.details == {"exception": "RuntimeError", "rule_id": "X_RULE"}
    assert "/etc/shadow" not in finding.evidence
    assert "Traceback" not in finding.evidence


def test_guard_records_the_originating_rule_for_package_level_failures(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)
    rule = _rule("ORIGIN_RULE", lambda inner: [])

    def _boom() -> list[Finding]:
        raise ZeroDivisionError

    findings = guard(context, rule, None, _boom)
    assert findings[0].details["rule_id"] == "ORIGIN_RULE"
    assert findings[0].path is None


def test_a_crashing_rule_does_not_stop_the_run(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)

    def _crash(inner: DiffContext) -> list[Finding]:
        raise ValueError("nope")

    findings = run_rules(context, registry=_registry(_rule("CRASHING_RULE", _crash)))
    assert [finding.rule_id for finding in findings] == [RULE_ENGINE_RULE_ID]
    assert findings[0].details["rule_id"] == "CRASHING_RULE"
    assert analysis_incomplete(findings) is True


def test_a_long_rule_id_crash_still_becomes_an_info_finding(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)
    long_id = "A" * 96

    def _crash(inner: DiffContext) -> list[Finding]:
        raise ValueError("nope")

    findings = run_rules(context, registry=_registry(_rule(long_id, _crash)))
    assert [finding.rule_id for finding in findings] == [RULE_ENGINE_RULE_ID]
    assert findings[0].details["rule_id"] == long_id[:64]
    assert analysis_incomplete(findings) is True


def test_per_file_failure_keeps_the_other_files(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)

    def _half_broken(inner: DiffContext) -> list[Finding]:
        rule = _rule("PARTIAL_RULE", lambda deeper: [])
        out: list[Finding] = []
        for path in sorted(inner.files_new):
            if path == "package/bad.js":
                out.extend(guard(inner, rule, path, _raise))
                continue
            out.extend(
                guard(
                    inner,
                    rule,
                    path,
                    lambda current=path: [_finding(inner, "PARTIAL_RULE", current, "hit")],
                )
            )
        return out

    def _raise() -> list[Finding]:
        raise ValueError("bad file")

    findings = run_rules(context, registry=_registry(_rule("PARTIAL_RULE", _half_broken)))
    errors = [finding for finding in findings if finding.rule_id == RULE_ENGINE_RULE_ID]
    hits = [finding for finding in findings if finding.rule_id == "PARTIAL_RULE"]

    assert [finding.path for finding in errors] == ["package/bad.js"]
    assert [finding.path for finding in hits] == ["package/a.js"]
    assert analysis_incomplete(findings) is True


def test_run_rules_is_deterministic(tmp_path: Path) -> None:
    first = rule_context(tmp_path, "JS_CHILD_PROCESS_ADDED", "positive")
    second = rule_context(tmp_path, "JS_CHILD_PROCESS_ADDED", "positive")
    assert [f.model_dump() for f in run_rules(first)] == [f.model_dump() for f in run_rules(second)]


def test_experimental_families_are_skipped_by_default(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)
    registry = _registry(
        _rule(
            "OBFUSCATION_RULE",
            lambda inner: [_finding(inner, "OBFUSCATION_RULE", "package/a.js", "hit")],
            families=(RuleFamily.OBFUSCATION,),
        ),
        _rule(
            "METADATA_RULE",
            lambda inner: [_finding(inner, "METADATA_RULE", None, "hit")],
            families=(RuleFamily.METADATA,),
        ),
        _rule(
            "CAPABILITY_RULE",
            lambda inner: [_finding(inner, "CAPABILITY_RULE", "package/a.js", "hit")],
        ),
    )

    default_ids = {finding.rule_id for finding in run_rules(context, registry=registry)}
    assert default_ids == {"CAPABILITY_RULE"}

    enabled_ids = {
        finding.rule_id for finding in run_rules(context, registry=registry, experimental=True)
    }
    assert enabled_ids == {"CAPABILITY_RULE", "OBFUSCATION_RULE", "METADATA_RULE"}


def test_run_rules_emits_in_registration_order(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)

    def _second(inner: DiffContext) -> list[Finding]:
        return [_finding(inner, "ZZ_SECOND_RULE", None, "b")]

    def _first(inner: DiffContext) -> list[Finding]:
        return [_finding(inner, "AA_FIRST_RULE", None, "a")]

    findings = run_rules(
        context,
        registry=_registry(_rule("AA_FIRST_RULE", _first), _rule("ZZ_SECOND_RULE", _second)),
    )
    assert [finding.rule_id for finding in findings] == ["AA_FIRST_RULE", "ZZ_SECOND_RULE"]


def test_rules_for_other_ecosystems_never_run(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)

    def _pypi_only(inner: DiffContext) -> list[Finding]:
        raise AssertionError("must not run for npm")

    findings = run_rules(
        context,
        registry=_registry(_rule("PY_RULE", _pypi_only, ecosystems=(Ecosystem.PYPI,))),
    )
    assert findings == []


def test_clean_run_is_not_marked_incomplete(tmp_path: Path) -> None:
    context = rule_context(tmp_path, "JS_CHILD_PROCESS_ADDED", "negative")
    assert analysis_incomplete(run_rules(context)) is False


def test_a_rule_returning_another_rule_id_is_reported_not_trusted(tmp_path: Path) -> None:
    context = ctx_from_files(tmp_path, *TWO_FILES)

    def _mislabeled(inner: DiffContext) -> list[Finding]:
        return [_finding(inner, "SOME_OTHER_RULE", None, "a")]

    findings = run_rules(context, registry=_registry(_rule("X_MISLABELLED_RULE", _mislabeled)))
    assert [finding.rule_id for finding in findings] == [RULE_ENGINE_RULE_ID]
    assert findings[0].details["rule_id"] == "X_MISLABELLED_RULE"
    assert findings[0].details["exception"] == "RuleContractViolation"


def test_a_view_the_diff_could_not_read_is_reported(tmp_path: Path) -> None:
    context = ctx_from_files(
        tmp_path,
        {"package/a.js": b"1234567890\n"},
        {"package/b.js": b"abcdefghij\n"},
        limits=SandboxLimits(max_total_uncompressed_bytes=15),
    )
    assert [error.path for error in context.parse_errors] == ["package/b.js"]

    findings = run_rules(context)
    engine = [finding for finding in findings if finding.rule_id == RULE_ENGINE_RULE_ID]
    assert [(finding.path, finding.details["kind"]) for finding in engine] == [
        ("package/b.js", "budget")
    ]
    assert all(finding.severity is Severity.INFO for finding in engine)
    assert analysis_incomplete(findings) is True
