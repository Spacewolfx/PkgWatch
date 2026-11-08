"""Scanning helpers shared by the rule families.

Rules are pure functions of a ``DiffContext`` (SPEC §4.1): no I/O, no clock, no package
paths beyond what the sandbox already validated. Everything that could be a source of
crashes lives here so the family modules stay pattern tables plus documentation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from pkgwatch.models import DiffContext, DiffLineOp, FileView, Finding, Severity

JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs")
ROOT_MANIFEST = "package/package.json"

FULL_SCAN = "full"
PARTIAL_SCAN = "partial"


@dataclass(frozen=True)
class Pattern:
    """A named regular expression. The name is what lands in ``details["pattern"]``."""

    name: str
    regex: re.Pattern[str]


def pattern(name: str, expression: str) -> Pattern:
    return Pattern(name=name, regex=re.compile(expression))


def finding(
    ctx: DiffContext,
    *,
    rule_id: str,
    rule_version: int,
    severity: Severity,
    evidence: str,
    path: str | None = None,
    line_start: int | None = None,
    line_end: int | None = None,
    details: dict[str, str | int | float | bool] | None = None,
) -> Finding:
    """One hit, with the release identity denormalised onto it (SPEC §4.3)."""
    return Finding(
        rule_id=rule_id,
        rule_version=rule_version,
        severity=severity,
        path=path,
        evidence=evidence,
        line_start=line_start,
        line_end=line_end,
        ecosystem=ctx.ecosystem,
        package_name=ctx.package_name,
        old_version=ctx.old_version,
        new_version=ctx.new_version,
        details=details or {},
    )


def added_lines(view: FileView) -> list[tuple[int, str]]:
    """``(1-based line in the new file, text)`` for every added line of a view."""
    return [
        (line.line_new, line.text)
        for line in view.diff_lines
        if line.op is DiffLineOp.ADD and line.line_new is not None
    ]


def text_views(views: Iterable[FileView], suffixes: Sequence[str] = JS_SUFFIXES) -> list[FileView]:
    """Text views whose path looks like source we can pattern-match."""
    return [
        view
        for view in sorted(views, key=lambda item: item.path)
        if view.is_text and view.path.lower().endswith(tuple(suffixes))
    ]


def old_tree_state(ctx: DiffContext) -> str:
    """Whether the old tree was scanned whole — family 2 must not claim more."""
    if ctx.views_incomplete:
        return PARTIAL_SCAN
    if any(view.truncated for view in ctx.files_old.values()):
        return PARTIAL_SCAN
    return FULL_SCAN


def old_tree_has_capability(ctx: DiffContext, item: Pattern) -> bool:
    """SPEC §4.5: "absent before" is decided against the whole old tree, not one file."""
    return any(
        item.regex.search(line)
        for view in text_views(ctx.files_old.values())
        for line in view.content.splitlines()
    )


def capability_findings(
    ctx: DiffContext,
    *,
    rule_id: str,
    rule_version: int,
    severity: Severity,
    patterns: Sequence[Pattern],
) -> list[Finding]:
    """Findings for added lines that introduce a capability the old tree lacked.

    One finding per matching line; the first pattern that matches a line wins, so a line
    that reads as two capabilities is reported once.
    """
    hits: list[tuple[int, str, str, Pattern]] = []
    for view in text_views(ctx.files_new.values()):
        for number, text in added_lines(view):
            for item in patterns:
                if item.regex.search(text):
                    hits.append((number, text, view.path, item))
                    break

    scan = old_tree_state(ctx)
    present = {item.name: old_tree_has_capability(ctx, item) for item in patterns}
    findings: list[Finding] = []
    for number, text, path, item in sorted(hits, key=lambda hit: (hit[2], hit[0])):
        if present[item.name]:
            continue
        findings.append(
            finding(
                ctx,
                rule_id=rule_id,
                rule_version=rule_version,
                severity=severity,
                path=path,
                evidence=text.strip(),
                line_start=number,
                line_end=number,
                details={"pattern": item.name, "old_tree_scan": scan},
            )
        )
    return findings


def root_manifest_additions(ctx: DiffContext) -> list[tuple[int, str]]:
    """Added lines of the package manifest at the tarball root; empty if it has no view."""
    view = ctx.files_new.get(ROOT_MANIFEST)
    if view is None or not view.is_text:
        return []
    return added_lines(view)


def declared_scripts(metadata: dict[str, Any]) -> dict[str, str]:
    """Install-visible ``scripts`` from registry metadata, skipping anything non-conforming.

    Registry JSON is hostile input: a list, number or null where a command string should be
    is ignored rather than raised on, because a weird manifest is not evidence of malice.
    """
    scripts = metadata.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {
        name: command
        for name, command in scripts.items()
        if isinstance(name, str) and isinstance(command, str)
    }
