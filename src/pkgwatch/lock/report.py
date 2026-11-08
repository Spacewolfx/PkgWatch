"""Report shaping for ``pkgwatch lock``: the JSON schema, the text formatter, ``--plan``.

The lock report carries its own ``schema_version`` (4) rather than reusing compare's: it
is a multi-package document with the plan sections (new, removed, skipped) that a
single-pair compare report does not have. Findings are ordered exactly as ``compare``
orders them, and a pair that failed is reported with its stable code instead of being
dropped, so SPEC §9.1(5) and §9.1(7) both hold in the output. Schema 4 carries a
``baselined`` count and an optional per-rule ``reason`` on every ``ignored_rules`` entry.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from typing import TypedDict

from pkgwatch.lock.run import LockRunResult, NewPackageAnalysis, PairAnalysis
from pkgwatch.lockfile import LockPlan
from pkgwatch.models import Ecosystem, Finding, Severity
from pkgwatch.rules import rule_set_version
from pkgwatch.rules.family4_metadata import DEPENDENCY_ADDED, REPOSITORY_URL_CHANGED

LOCK_JSON_SCHEMA_VERSION = 4

# One short report: findings per pair are capped in text mode unless --verbose.
FINDINGS_PER_PAIR_LIMIT = 10

_SEVERITY_ORDER = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)
NOT_AVAILABLE = "(not available)"


class FindingOut(TypedDict):
    rule_id: str
    severity: str
    path: str | None
    line: int | None
    evidence: str
    details: dict[str, str | int | float | bool]


class BoostOut(TypedDict):
    name: str
    points: int


class FileCountsOut(TypedDict):
    added: int
    removed: int
    modified: int


class PairOut(TypedDict):
    name: str
    old_version: str
    new_version: str
    score: int
    findings: list[FindingOut]
    findings_omitted: int
    boosts: list[BoostOut]
    digests: dict[str, str] | None
    files: FileCountsOut
    error: str | None
    parse_problems: list[str]


class NewAnalysisOut(TypedDict):
    score: int
    findings: list[FindingOut]
    findings_omitted: int
    boosts: list[BoostOut]
    digest: str | None
    files: FileCountsOut
    informational: dict[str, int]
    error: str | None
    parse_problems: list[str]


class NewPackageOut(TypedDict):
    name: str
    version: str
    has_install_script: bool | None
    analysis: NewAnalysisOut | None


class SkipOut(TypedDict):
    side: str
    name: str
    version: str | None
    reason: str


class IgnoredRuleOut(TypedDict):
    rule_id: str
    findings: int
    reason: str | None


class UnanalysedOut(TypedDict):
    name: str
    old_version: str | None
    new_version: str | None
    reason: str


class PlanPairOut(TypedDict):
    name: str
    old_version: str
    new_version: str


class PlanNewOut(TypedDict):
    name: str
    version: str
    has_install_script: bool | None


class PlanOut(TypedDict):
    lockfile_versions: dict[str, int]
    changed_pairs: list[PlanPairOut]
    new_packages: list[PlanNewOut]
    removed_packages: list[str]
    skipped: list[SkipOut]
    unanalysed_packages: list[UnanalysedOut]


class LockReport(TypedDict):
    schema_version: int
    ecosystem: str
    old_lockfile: str
    new_lockfile: str
    lockfile_versions: dict[str, int]
    pairs: list[PairOut]
    new_packages: list[NewPackageOut]
    new_packages_analysed: bool
    removed_packages: list[str]
    skipped: list[SkipOut]
    unanalysed: int
    unanalysed_packages: list[UnanalysedOut]
    ignored_rules: list[IgnoredRuleOut]
    baselined: int
    rule_set_version: str
    analysis_incomplete: bool
    measured: bool
    disclaimer: str


def build_report(
    result: LockRunResult,
    *,
    old_lockfile: str,
    new_lockfile: str,
    verbose: bool,
    disclaimer: str,
    ignored_reasons: Mapping[str, str] = {},
) -> LockReport:
    plan = result.plan
    analyses = {(item.name, item.version): item for item in result.new_analyses}
    baselined = sum(item.baselined for item in result.pairs) + sum(
        item.baselined for item in result.new_analyses
    )
    return LockReport(
        schema_version=LOCK_JSON_SCHEMA_VERSION,
        ecosystem=Ecosystem.NPM.value,
        old_lockfile=old_lockfile,
        new_lockfile=new_lockfile,
        lockfile_versions={
            "old": plan.old_lockfile_version,
            "new": plan.new_lockfile_version,
        },
        pairs=[_pair_out(item, verbose=verbose) for item in result.pairs],
        new_packages=[
            NewPackageOut(
                name=item.name,
                version=item.version,
                has_install_script=item.has_install_script,
                analysis=(
                    _new_analysis_out(analyses[(item.name, item.version)], verbose=verbose)
                    if (item.name, item.version) in analyses
                    else None
                ),
            )
            for item in plan.new_packages
        ],
        new_packages_analysed=result.new_analysed,
        removed_packages=list(plan.removed_packages),
        skipped=[
            SkipOut(
                side=item.side.value,
                name=item.name,
                version=item.version,
                reason=item.reason.value,
            )
            for item in plan.skipped
        ],
        unanalysed=len(plan.unanalysed),
        unanalysed_packages=[
            UnanalysedOut(
                name=item.name,
                old_version=item.old_version,
                new_version=item.new_version,
                reason=item.reason.value,
            )
            for item in plan.unanalysed
        ],
        ignored_rules=_ignored_rules(result.pairs, result.new_analyses, ignored_reasons),
        baselined=baselined,
        rule_set_version=rule_set_version(),
        analysis_incomplete=result.incomplete,
        measured=False,
        disclaimer=disclaimer,
    )


def _pair_out(pair: PairAnalysis, *, verbose: bool) -> PairOut:
    display = sorted(pair.findings, key=_display_order)
    shown = display if verbose else display[:FINDINGS_PER_PAIR_LIMIT]
    added, removed, modified = pair.files
    return PairOut(
        name=pair.name,
        old_version=pair.old_version,
        new_version=pair.new_version,
        score=pair.score,
        findings=_findings_out(shown),
        findings_omitted=len(display) - len(shown),
        boosts=[BoostOut(name=item.name, points=item.points) for item in pair.boosts],
        digests=None if pair.digests is None else {"old": pair.digests[0], "new": pair.digests[1]},
        files=FileCountsOut(added=added, removed=removed, modified=modified),
        error=pair.error,
        parse_problems=list(pair.parse_problems),
    )


def _new_analysis_out(analysis: NewPackageAnalysis, *, verbose: bool) -> NewAnalysisOut:
    display = sorted(analysis.findings, key=_display_order)
    shown = display if verbose else display[:FINDINGS_PER_PAIR_LIMIT]
    added, removed, modified = analysis.files
    return NewAnalysisOut(
        score=analysis.score,
        findings=_findings_out(shown),
        findings_omitted=len(display) - len(shown),
        boosts=[BoostOut(name=item.name, points=item.points) for item in analysis.boosts],
        digest=analysis.digest,
        files=FileCountsOut(added=added, removed=removed, modified=modified),
        informational=dict(analysis.informational),
        error=analysis.error,
        parse_problems=list(analysis.parse_problems),
    )


def _findings_out(findings: Sequence[Finding]) -> list[FindingOut]:
    return [
        FindingOut(
            rule_id=item.rule_id,
            severity=item.severity.value,
            path=item.path,
            line=item.line_start,
            evidence=item.evidence,
            details=dict(item.details),
        )
        for item in findings
    ]


def _ignored_rules(
    pairs: Sequence[PairAnalysis],
    new_analyses: Sequence[NewPackageAnalysis],
    reasons: Mapping[str, str],
) -> list[IgnoredRuleOut]:
    totals: dict[str, int] = {}
    items: list[PairAnalysis | NewPackageAnalysis] = [*pairs, *new_analyses]
    for item in items:
        for rule_id, count in item.ignored:
            totals[rule_id] = totals.get(rule_id, 0) + count
    return [
        IgnoredRuleOut(rule_id=rule_id, findings=count, reason=reasons.get(rule_id))
        for rule_id, count in sorted(totals.items())
    ]


def _display_order(item: Finding) -> tuple[int, str, str, int]:
    """Severity highest first, then rule_id, path, line — the compare order."""
    return (
        -_SEVERITY_ORDER.index(item.severity),
        item.rule_id,
        item.path or "",
        item.line_start or 0,
    )


def format_text(report: LockReport) -> str:
    versions = report["lockfile_versions"]
    analysed = [pair for pair in report["pairs"] if pair["error"] is None]
    failed = [pair for pair in report["pairs"] if pair["error"] is not None]
    new_ok = [
        item
        for item in report["new_packages"]
        if item["analysis"] is not None and item["analysis"]["error"] is None
    ]
    new_failed = [
        item
        for item in report["new_packages"]
        if item["analysis"] is not None and item["analysis"]["error"] is not None
    ]

    lines = [
        f"lock: package-lock v{versions['old']} -> v{versions['new']}",
        f"packages: {len(analysed)} analysed pairs, {len(new_ok)} analysed new packages, "
        f"{report['unanalysed']} unanalysed, {len(failed) + len(new_failed)} failed, "
        f"{len(report['new_packages'])} new, "
        f"{len(report['removed_packages'])} removed, {len(report['skipped'])} skipped",
    ]
    if not report["new_packages_analysed"]:
        lines.append("new packages were NOT analysed (--no-new).")
    if report["unanalysed"]:
        lines.append(
            f"WARNING: {report['unanalysed']} package(s) could not be analysed; "
            "a missing analysis is not a clean result."
        )

    if analysed:
        lines.append("changed pairs:")
        for pair in analysed:
            lines.extend(_pair_lines(pair))
    else:
        lines.append("changed pairs: (none)")

    if failed:
        lines.append("failed pairs:")
        for pair in failed:
            lines.append(
                f"  {pair['name']} {pair['old_version']} -> {pair['new_version']} {pair['error']}"
            )
            if pair["parse_problems"]:
                lines.append(f"    parse problems: {', '.join(pair['parse_problems'])}")

    lines.append("unanalysed packages:")
    for item in report["unanalysed_packages"]:
        versions_text = _version_span(item["old_version"], item["new_version"])
        prefix = f"  {_one_line(item['name'])}"
        if versions_text:
            prefix += f" {versions_text}"
        lines.append(f"{prefix} {item['reason']}")
    if not report["unanalysed_packages"]:
        lines.append("  (none)")

    lines.append("new packages (no baseline):")
    if report["new_packages_analysed"] and report["new_packages"]:
        lines.append(
            "  findings are expected to be noisier with no old version to diff against; "
            "only lifecycle findings affect the exit code."
        )
    for added in report["new_packages"]:
        lines.extend(_new_package_lines(added))
    if not report["new_packages"]:
        lines.append("  (none)")

    lines.append("removed packages:")
    for name in report["removed_packages"]:
        lines.append(f"  {_one_line(name)}")
    if not report["removed_packages"]:
        lines.append("  (none)")

    lines.append("skipped:")
    for skip in report["skipped"]:
        version = skip["version"] if skip["version"] is not None else NOT_AVAILABLE
        lines.append(
            f"  {skip['side']} {_one_line(skip['name'])} {_one_line(version)} {skip['reason']}"
        )
    if not report["skipped"]:
        lines.append("  (none)")

    for ignored in report["ignored_rules"]:
        line = f"ignored: {ignored['rule_id']} ({ignored['findings']} findings)"
        if ignored["reason"] is not None:
            line += f" — {_one_line(ignored['reason'])}"
        lines.append(line)

    if report["baselined"]:
        lines.append(f"baselined: {report['baselined']} findings")

    return "\n".join(lines)


def _pair_lines(pair: PairOut) -> list[str]:
    total = len(pair["findings"]) + pair["findings_omitted"]
    lines = [
        f"  {pair['name']} {pair['old_version']} -> {pair['new_version']}"
        f"  score {pair['score']}  findings {total}"
    ]
    lines.extend(_finding_lines(pair["findings"], pair["findings_omitted"], pair["boosts"]))
    if pair["digests"] is not None:
        lines.append(f"    digests: old={pair['digests']['old']}, new={pair['digests']['new']}")
    return lines


def _new_package_lines(added: NewPackageOut) -> list[str]:
    suffix = " install-script" if added["has_install_script"] else ""
    head = f"  {_one_line(added['name'])} {_one_line(added['version'])}{suffix}"
    analysis = added["analysis"]
    if analysis is None:
        return [head]
    if analysis["error"] is not None:
        lines = [f"{head}  {analysis['error']}"]
        if analysis["parse_problems"]:
            lines.append(f"    parse problems: {', '.join(analysis['parse_problems'])}")
        return lines
    total = len(analysis["findings"]) + analysis["findings_omitted"]
    lines = [f"{head}  score {analysis['score']}  findings {total}"]
    lines.extend(
        _finding_lines(analysis["findings"], analysis["findings_omitted"], analysis["boosts"])
    )
    if analysis["informational"]:
        lines.append(
            f"    metadata (informational): {_informational_text(analysis['informational'])}"
        )
    if analysis["digest"] is not None:
        lines.append(f"    digest: {analysis['digest']}")
    return lines


def _informational_text(counts: dict[str, int]) -> str:
    """One plain line for the family-4 metadata a new package carries but never scored."""
    parts: list[str] = []
    for rule_id, count in sorted(counts.items()):
        if rule_id == DEPENDENCY_ADDED:
            parts.append(f"{count} " + ("dependency" if count == 1 else "dependencies"))
        elif rule_id == REPOSITORY_URL_CHANGED:
            parts.append("repository present")
        else:
            parts.append(f"{_one_line(rule_id)} ({count})")
    return ", ".join(parts)


def _finding_lines(
    findings: Sequence[FindingOut], omitted: int, boosts: Sequence[BoostOut]
) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        location = _location(finding)
        lines.append(
            f"    {finding['rule_id']} {finding['severity']} {location} "
            f"{_one_line(finding['evidence'])}"
        )
        if finding["details"]:
            lines.append(f"      details: {_format_details(finding['details'])}")
    if omitted:
        lines.append(f"    ... {omitted} more")
    if boosts:
        lines.append(
            "    boosts: " + " ".join(f"{item['name']} +{item['points']}" for item in boosts)
        )
    return lines


def _location(finding: FindingOut) -> str:
    """A finding without a path or line is package-level, not a dash pair."""
    if finding["path"] is None and finding["line"] is None:
        return "(package-level)"
    path = _one_line(finding["path"] or "-")
    line = "-" if finding["line"] is None else str(finding["line"])
    return f"{path}:{line}"


def _format_details(details: dict[str, str | int | float | bool]) -> str:
    return " ".join(
        f"{_one_line(key)}={_one_line(str(value))}" for key, value in sorted(details.items())
    )


def _version_span(old: str | None, new: str | None) -> str:
    if old is not None and new is not None:
        return f"{old} -> {new}"
    if old is not None:
        return old
    if new is not None:
        return new
    return ""


def _one_line(text: str) -> str:
    """Lockfile- and package-controlled text stays on one printable line."""
    return "".join(" " if ord(char) < 0x20 or char == "\x7f" else char for char in text)


def build_plan_json(plan: LockPlan) -> PlanOut:
    """The ``--plan`` document: the plan sections, and nothing else (no analysis yet)."""
    return PlanOut(
        lockfile_versions={
            "old": plan.old_lockfile_version,
            "new": plan.new_lockfile_version,
        },
        changed_pairs=[
            PlanPairOut(name=item.name, old_version=item.old_version, new_version=item.new_version)
            for item in plan.changed_pairs
        ],
        new_packages=[
            PlanNewOut(
                name=item.name,
                version=item.version,
                has_install_script=item.has_install_script,
            )
            for item in plan.new_packages
        ],
        removed_packages=list(plan.removed_packages),
        skipped=[
            SkipOut(
                side=item.side.value,
                name=item.name,
                version=item.version,
                reason=item.reason.value,
            )
            for item in plan.skipped
        ],
        unanalysed_packages=[
            UnanalysedOut(
                name=item.name,
                old_version=item.old_version,
                new_version=item.new_version,
                reason=item.reason.value,
            )
            for item in plan.unanalysed
        ],
    )


def format_plan_text(plan: LockPlan) -> str:
    """The ``--plan`` view: same sections as the report, with reason codes, no analysis."""
    lines = [
        f"lock: package-lock v{plan.old_lockfile_version} -> v{plan.new_lockfile_version} (plan)"
    ]

    lines.append("changed pairs:")
    for pair in plan.changed_pairs:
        lines.append(f"  {_one_line(pair.name)} {pair.old_version} -> {pair.new_version}")
    if not plan.changed_pairs:
        lines.append("  (none)")

    lines.append("unanalysed packages:")
    for item in plan.unanalysed:
        versions_text = _version_span(item.old_version, item.new_version)
        prefix = f"  {_one_line(item.name)}"
        if versions_text:
            prefix += f" {versions_text}"
        lines.append(f"{prefix} {item.reason.value}")
    if not plan.unanalysed:
        lines.append("  (none)")

    lines.append("new packages:")
    for added in plan.new_packages:
        suffix = " install-script" if added.has_install_script else ""
        lines.append(f"  {_one_line(added.name)} {_one_line(added.version)}{suffix}")
    if not plan.new_packages:
        lines.append("  (none)")

    lines.append("removed packages:")
    for name in plan.removed_packages:
        lines.append(f"  {_one_line(name)}")
    if not plan.removed_packages:
        lines.append("  (none)")

    lines.append("skipped:")
    for skip in plan.skipped:
        version = skip.version if skip.version is not None else NOT_AVAILABLE
        lines.append(
            f"  {skip.side.value} {_one_line(skip.name)} {_one_line(version)} {skip.reason.value}"
        )
    if not plan.skipped:
        lines.append("  (none)")

    return "\n".join(lines)


# Markdown evidence is hard-capped, like the model's own cap, so a PR comment stays small.
EVIDENCE_MD_LIMIT = 200


def format_markdown(report: LockReport) -> str:
    """The same report as Markdown: one collapsible block per section.

    Every package-controlled string is escaped for Markdown and HTML, and evidence is
    capped at 200 characters. The disclaimer is printed by the CLI, as in text mode.
    """
    analysed = [pair for pair in report["pairs"] if pair["error"] is None]
    failed = [pair for pair in report["pairs"] if pair["error"] is not None]
    new_ok = [
        item
        for item in report["new_packages"]
        if item["analysis"] is not None and item["analysis"]["error"] is None
    ]
    new_failed = [
        item
        for item in report["new_packages"]
        if item["analysis"] is not None and item["analysis"]["error"] is not None
    ]
    total_failed = len(failed) + len(new_failed)

    lines = [
        "### pkgwatch lock report",
        "",
        f"packages: {len(analysed)} analysed pairs, {len(new_ok)} analysed new packages, "
        f"{report['unanalysed']} unanalysed, {total_failed} failed, "
        f"{len(report['new_packages'])} new, "
        f"{len(report['removed_packages'])} removed, {len(report['skipped'])} skipped",
    ]
    if not report["new_packages_analysed"]:
        lines.append("new packages were NOT analysed (--no-new).")
    if report["unanalysed"]:
        lines.append(
            f"WARNING: {report['unanalysed']} package(s) could not be analysed; "
            "a missing analysis is not a clean result."
        )

    if analysed:
        lines.append("")
        lines.append(f"<details><summary>changed pairs ({len(analysed)})</summary>")
        lines.append("")
        for pair in analysed:
            total = len(pair["findings"]) + pair["findings_omitted"]
            lines.append(f"#### {_md(pair['name'])} {pair['old_version']} -> {pair['new_version']}")
            lines.append(f"score {pair['score']}, {total} findings")
            lines.extend(_md_findings(pair["findings"], pair["findings_omitted"]))
            if pair["boosts"]:
                lines.append(
                    "boosts: "
                    + ", ".join(f"{item['name']} +{item['points']}" for item in pair["boosts"])
                )
            if pair["digests"] is not None:
                lines.append(f"digests: old={pair['digests']['old']}, new={pair['digests']['new']}")
        lines.append("")
        lines.append("</details>")

    if failed or new_failed:
        lines.append("")
        lines.append(f"<details><summary>failed pairs ({total_failed})</summary>")
        lines.append("")
        for pair in failed:
            lines.append(
                f"- `{_md(pair['name'])}` {pair['old_version']} -> {pair['new_version']}"
                f": {pair['error']}"
            )
            if pair["parse_problems"]:
                lines.append(f"  parse problems: {', '.join(pair['parse_problems'])}")
        for item in new_failed:
            analysis = item["analysis"]
            if analysis is None:
                continue
            lines.append(f"- `{_md(item['name'])}` {item['version']}: {analysis['error']}")
        lines.append("")
        lines.append("</details>")

    if report["unanalysed_packages"]:
        lines.append("")
        lines.append(f"<details><summary>unanalysed packages ({report['unanalysed']})</summary>")
        lines.append("")
        for entry in report["unanalysed_packages"]:
            span = _version_span(entry["old_version"], entry["new_version"])
            listing = f"{_md(entry['name'])} {span} {entry['reason']}".strip()
            lines.append(f"- `{listing}`")
        lines.append("")
        lines.append("</details>")

    if report["new_packages"]:
        lines.append("")
        count = len(report["new_packages"])
        lines.append(f"<details><summary>new packages (no baseline) ({count})</summary>")
        lines.append("")
        if report["new_packages_analysed"]:
            lines.append(
                "Findings are expected to be noisier with no old version to diff against; "
                "only lifecycle findings affect the exit code."
            )
        lines.append("")
        for added in report["new_packages"]:
            suffix = " install-script" if added["has_install_script"] else ""
            lines.append(f"#### {_md(added['name'])} {added['version']}{suffix}")
            analysis = added["analysis"]
            if analysis is None:
                continue
            if analysis["error"] is not None:
                lines.append(f"error: {analysis['error']}")
                continue
            total = len(analysis["findings"]) + analysis["findings_omitted"]
            lines.append(f"score {analysis['score']}, {total} findings")
            lines.extend(_md_findings(analysis["findings"], analysis["findings_omitted"]))
            if analysis["informational"]:
                lines.append(
                    f"metadata (informational): {_informational_text(analysis['informational'])}"
                )
        lines.append("")
        lines.append("</details>")

    if report["removed_packages"]:
        lines.append("")
        lines.append(
            f"<details><summary>removed packages ({len(report['removed_packages'])})</summary>"
        )
        lines.append("")
        for name in report["removed_packages"]:
            lines.append(f"- `{_md(name)}`")
        lines.append("")
        lines.append("</details>")

    if report["skipped"]:
        lines.append("")
        lines.append(f"<details><summary>skipped ({len(report['skipped'])})</summary>")
        lines.append("")
        for skip in report["skipped"]:
            version = skip["version"] if skip["version"] is not None else NOT_AVAILABLE
            lines.append(f"- {skip['side']} `{_md(skip['name'])}` {_md(version)}: {skip['reason']}")
        lines.append("")
        lines.append("</details>")

    if report["ignored_rules"]:
        lines.append("")
        lines.append(f"<details><summary>ignored ({len(report['ignored_rules'])})</summary>")
        lines.append("")
        for ignored in report["ignored_rules"]:
            reason = "" if ignored["reason"] is None else f" — {_md(ignored['reason'])}"
            lines.append(f"- `{ignored['rule_id']}` ({ignored['findings']} findings){reason}")
        lines.append("")
        lines.append("</details>")

    if report["baselined"]:
        lines.append("")
        lines.append(f"Baselined: {report['baselined']} findings hidden by the baseline.")

    return "\n".join(lines)


def _md_findings(findings: Sequence[FindingOut], omitted: int) -> list[str]:
    lines: list[str] = []
    for finding in findings:
        evidence = _clip(finding["evidence"])
        lines.append(
            f"- `{finding['rule_id']}` {finding['severity']}, "
            f"{_md(_location(finding))}: {_md(evidence)}"
        )
    if omitted:
        lines.append(f"- ... {omitted} more")
    return lines


def _md(text: str) -> str:
    """Escape a package-controlled string for Markdown and HTML."""
    escaped = html.escape(_one_line(text), quote=True)
    for char in "\\`*_[]":
        escaped = escaped.replace(char, f"\\{char}")
    return escaped


def _clip(text: str, limit: int = EVIDENCE_MD_LIMIT) -> str:
    """Evidence shows at most ``limit`` characters, then an ellipsis."""
    single = _one_line(text)
    if len(single) <= limit:
        return single
    return single[:limit] + "…"
