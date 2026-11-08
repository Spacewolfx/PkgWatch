"""Report shaping for ``pkgwatch lock``: capping, ordering and the failed-pair section."""

from __future__ import annotations

from pkgwatch.lock.report import (
    FINDINGS_PER_PAIR_LIMIT,
    LockReport,
    build_report,
    format_markdown,
    format_text,
)
from pkgwatch.lock.run import LockRunResult, NewPackageAnalysis, PairAnalysis
from pkgwatch.lockfile import LockPlan, NewPackage, SkipReason, UnanalysedPackage
from pkgwatch.models import Ecosystem, Finding, Severity

DISCLAIMER = "test disclaimer"


def _finding(rule_id: str, severity: Severity, line: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=1,
        severity=severity,
        path="index.js",
        evidence=f"evidence {line}",
        line_start=line,
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="2.0.0",
    )


def _pair(
    findings: tuple[Finding, ...] = (),
    *,
    score: int = 0,
    error: str | None = None,
    parse_problems: tuple[str, ...] = (),
    ignored: tuple[tuple[str, int], ...] = (),
    baselined: int = 0,
) -> PairAnalysis:
    return PairAnalysis(
        name="demo-pkg",
        old_version="1.0.0",
        new_version="2.0.0",
        findings=findings,
        score=score,
        error=error,
        parse_problems=parse_problems,
        ignored=ignored,
        baselined=baselined,
    )


def _build(
    *pairs: PairAnalysis,
    verbose: bool = False,
    unanalysed: tuple[UnanalysedPackage, ...] = (),
    new_packages: tuple[NewPackage, ...] = (),
    new_analyses: tuple[NewPackageAnalysis, ...] = (),
    new_analysed: bool = True,
    ignored_reasons: dict[str, str] | None = None,
) -> LockReport:
    result = LockRunResult(
        plan=LockPlan(
            old_lockfile_version=3,
            new_lockfile_version=3,
            changed_pairs=(),
            new_packages=new_packages,
            removed_packages=(),
            skipped=(),
            unanalysed=unanalysed,
        ),
        pairs=pairs,
        new_analyses=new_analyses,
        new_analysed=new_analysed,
    )
    return build_report(
        result,
        old_lockfile="old.json",
        new_lockfile="new.json",
        verbose=verbose,
        disclaimer=DISCLAIMER,
        ignored_reasons=ignored_reasons or {},
    )


def test_findings_are_capped_per_pair_unless_verbose() -> None:
    # README documents "the first 10"; pin the value, not just the mechanism.
    assert FINDINGS_PER_PAIR_LIMIT == 10
    total = FINDINGS_PER_PAIR_LIMIT + 2
    findings = tuple(
        _finding("DYNAMIC_EVAL_ADDED", Severity.CRITICAL, line) for line in range(1, total + 1)
    )

    capped = _build(_pair(findings, score=94))
    assert len(capped["pairs"][0]["findings"]) == FINDINGS_PER_PAIR_LIMIT
    assert capped["pairs"][0]["findings_omitted"] == 2
    assert "... 2 more" in format_text(capped)

    full = _build(_pair(findings, score=94), verbose=True)
    assert len(full["pairs"][0]["findings"]) == total
    assert full["pairs"][0]["findings_omitted"] == 0


def test_findings_are_ordered_by_severity_then_rule_id() -> None:
    findings = (
        _finding("AAA_LOW", Severity.LOW, 1),
        _finding("ZZZ_CRITICAL", Severity.CRITICAL, 2),
        _finding("BBB_MEDIUM", Severity.MEDIUM, 3),
    )

    pair = _build(_pair(findings), verbose=True)["pairs"][0]

    assert [item["rule_id"] for item in pair["findings"]] == [
        "ZZZ_CRITICAL",
        "BBB_MEDIUM",
        "AAA_LOW",
    ]


def test_a_failed_pair_is_reported_with_its_code_and_never_scored() -> None:
    report = _build(_pair(error="DIGEST_MISMATCH"))
    text = format_text(report)

    assert report["analysis_incomplete"] is True
    assert report["pairs"][0]["error"] == "DIGEST_MISMATCH"
    assert report["pairs"][0]["score"] == 0
    assert "changed pairs: (none)" in text
    assert "failed pairs:" in text
    assert "demo-pkg 1.0.0 -> 2.0.0 DIGEST_MISMATCH" in text


def test_parse_problems_are_listed_under_the_failed_pair() -> None:
    report = _build(_pair(error="ANALYSIS_INCOMPLETE", parse_problems=("MANIFEST_INVALID_JSON",)))

    assert "parse problems: MANIFEST_INVALID_JSON" in format_text(report)


def test_ignored_counts_are_summed_across_pairs() -> None:
    first = _pair(ignored=(("DYNAMIC_EVAL_ADDED", 2),))
    second = _pair(ignored=(("DYNAMIC_EVAL_ADDED", 1), ("JS_CHILD_PROCESS_ADDED", 1)))

    report = _build(first, second)

    assert report["ignored_rules"] == [
        {"rule_id": "DYNAMIC_EVAL_ADDED", "findings": 3, "reason": None},
        {"rule_id": "JS_CHILD_PROCESS_ADDED", "findings": 1, "reason": None},
    ]
    assert "ignored: DYNAMIC_EVAL_ADDED (3 findings)" in format_text(report)


def test_unanalysed_packages_are_counted_listed_and_warned_about() -> None:
    unanalysed = (
        UnanalysedPackage(
            name="git-pkg",
            old_version="1.0.0",
            new_version="2.0.0",
            reason=SkipReason.GIT_SOURCE,
        ),
    )

    report = _build(unanalysed=unanalysed)
    text = format_text(report)

    assert report["unanalysed"] == 1
    assert report["unanalysed_packages"] == [
        {
            "name": "git-pkg",
            "old_version": "1.0.0",
            "new_version": "2.0.0",
            "reason": "GIT_SOURCE",
        }
    ]
    assert "1 unanalysed" in text
    assert "WARNING" in text
    assert "not a clean result" in text
    assert "unanalysed packages:" in text
    assert "git-pkg 1.0.0 -> 2.0.0 GIT_SOURCE" in text


def test_new_packages_have_their_own_no_baseline_section() -> None:
    analysis = NewPackageAnalysis(
        name="added-pkg",
        version="2.0.0",
        findings=(_finding("NPM_INSTALL_SCRIPT_ADDED", Severity.HIGH, 1),),
        score=40,
        digest="integrity",
    )

    report = _build(
        new_packages=(NewPackage(name="added-pkg", version="2.0.0", has_install_script=True),),
        new_analyses=(analysis,),
    )
    text = format_text(report)

    assert report["new_packages_analysed"] is True
    assert report["new_packages"][0]["analysis"] is not None
    assert report["new_packages"][0]["analysis"]["score"] == 40
    assert report["new_packages"][0]["analysis"]["digest"] == "integrity"
    assert "new packages (no baseline):" in text
    assert "noisier" in text
    assert "added-pkg 2.0.0 install-script  score 40  findings 1" in text
    assert "NPM_INSTALL_SCRIPT_ADDED high index.js:1" in text
    # Never mixed with the changed pairs.
    assert "changed pairs: (none)" in text


def test_no_new_says_new_packages_were_not_analysed() -> None:
    report = _build(
        new_packages=(NewPackage(name="added-pkg", version="2.0.0", has_install_script=True),),
        new_analysed=False,
    )
    text = format_text(report)

    assert report["new_packages_analysed"] is False
    assert report["new_packages"][0]["analysis"] is None
    assert "new packages were NOT analysed (--no-new)" in text
    assert "added-pkg 2.0.0 install-script" in text


def test_a_failed_new_package_is_shown_with_its_code_and_marks_the_run_incomplete() -> None:
    report = _build(
        new_packages=(NewPackage(name="broken-pkg", version="2.0.0", has_install_script=None),),
        new_analyses=(
            NewPackageAnalysis(name="broken-pkg", version="2.0.0", error="DIGEST_MISMATCH"),
        ),
    )
    text = format_text(report)

    assert report["analysis_incomplete"] is True
    assert report["new_packages"][0]["analysis"]["error"] == "DIGEST_MISMATCH"
    assert "broken-pkg 2.0.0  DIGEST_MISMATCH" in text


def test_ignored_counts_include_new_package_analyses() -> None:
    report = _build(
        _pair(ignored=(("DYNAMIC_EVAL_ADDED", 1),)),
        new_packages=(NewPackage(name="added-pkg", version="2.0.0", has_install_script=None),),
        new_analyses=(
            NewPackageAnalysis(
                name="added-pkg",
                version="2.0.0",
                ignored=(("DYNAMIC_EVAL_ADDED", 2),),
            ),
        ),
    )

    assert report["ignored_rules"] == [
        {"rule_id": "DYNAMIC_EVAL_ADDED", "findings": 3, "reason": None}
    ]
    assert "ignored: DYNAMIC_EVAL_ADDED (3 findings)" in format_text(report)


def test_a_package_level_finding_prints_package_level_not_a_dash() -> None:
    package_level = Finding(
        rule_id="DEPENDENCY_ADDED",
        rule_version=1,
        severity=Severity.LOW,
        path=None,
        evidence="new dependency: left-pad",
        line_start=None,
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    report = _build(_pair(findings=(package_level,), score=4))
    text = format_text(report)

    assert "DEPENDENCY_ADDED low (package-level) new dependency: left-pad" in text
    assert "-:-" not in text


def test_the_header_labels_analysed_pairs_and_new_packages() -> None:
    report = _build(
        _pair(),
        new_packages=(NewPackage(name="added-pkg", version="2.0.0", has_install_script=None),),
        new_analyses=(NewPackageAnalysis(name="added-pkg", version="2.0.0"),),
    )
    text = format_text(report)

    assert "1 analysed pairs" in text
    assert "1 analysed new packages" in text
    assert "0 unanalysed" in text


def test_metadata_counts_render_as_one_informational_line_and_json_counts() -> None:
    report = _build(
        new_packages=(NewPackage(name="meta-pkg", version="2.0.0", has_install_script=None),),
        new_analyses=(
            NewPackageAnalysis(
                name="meta-pkg",
                version="2.0.0",
                informational=(("DEPENDENCY_ADDED", 2), ("REPOSITORY_URL_CHANGED", 1)),
            ),
        ),
    )
    text = format_text(report)

    assert "metadata (informational): 2 dependencies, repository present" in text
    assert report["new_packages"][0]["analysis"]["informational"] == {
        "DEPENDENCY_ADDED": 2,
        "REPOSITORY_URL_CHANGED": 1,
    }
    assert report["new_packages"][0]["analysis"]["findings"] == []


def test_an_ignored_rule_shows_its_reason_when_one_was_given() -> None:
    report = _build(
        _pair(ignored=(("DYNAMIC_EVAL_ADDED", 2),)),
        ignored_reasons={"DYNAMIC_EVAL_ADDED": "generator of providers"},
    )
    text = format_text(report)

    assert report["ignored_rules"] == [
        {"rule_id": "DYNAMIC_EVAL_ADDED", "findings": 2, "reason": "generator of providers"}
    ]
    assert "ignored: DYNAMIC_EVAL_ADDED (2 findings)" in text
    assert "generator of providers" in text


def test_an_ignored_rule_without_a_reason_has_a_null_reason() -> None:
    report = _build(_pair(ignored=(("DYNAMIC_EVAL_ADDED", 1),)))

    assert report["ignored_rules"] == [
        {"rule_id": "DYNAMIC_EVAL_ADDED", "findings": 1, "reason": None}
    ]
    assert " — " not in format_text(report)


def test_baselined_findings_are_counted_and_printed() -> None:
    report = _build(_pair(baselined=3), _pair(baselined=1))
    text = format_text(report)

    assert report["baselined"] == 4
    assert "baselined: 4 findings" in text


def test_no_baselined_findings_no_line_and_a_zero_count() -> None:
    report = _build(_pair())

    assert report["baselined"] == 0
    assert "baselined:" not in format_text(report)


def test_markdown_collapses_sections_and_keeps_the_disclaimer() -> None:
    findings = (_finding("DYNAMIC_EVAL_ADDED", Severity.CRITICAL, 3),)
    report = _build(_pair(findings, score=94))
    md = format_markdown(report)

    assert "### pkgwatch lock report" in md
    assert "<details>" in md
    assert "<summary>changed pairs" in md
    assert "demo-pkg" in md
    assert "DYNAMIC_EVAL_ADDED" in md


def test_markdown_escapes_hostile_strings_and_caps_evidence() -> None:
    hostile = Finding(
        rule_id="DYNAMIC_EVAL_ADDED",
        rule_version=1,
        severity=Severity.CRITICAL,
        path="evil-<script>.js",
        evidence="<script>`alert(1)`*x</script>" + "y" * 300,
        line_start=1,
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="2.0.0",
    )
    md = format_markdown(_build(_pair(findings=(hostile,), score=10)))

    assert "<script>" not in md
    assert "&lt;script&gt;" in md
    assert "\\`alert(1)\\`" in md
    assert "y" * 201 not in md
    assert "…" in md


def test_markdown_never_shows_a_dash_pair_for_package_level_findings() -> None:
    package_level = Finding(
        rule_id="DEPENDENCY_ADDED",
        rule_version=1,
        severity=Severity.LOW,
        path=None,
        evidence="new dependency: left-pad",
        line_start=None,
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="2.0.0",
    )

    md = format_markdown(_build(_pair(findings=(package_level,), score=4)))

    assert "(package-level)" in md
    assert "-:-" not in md
