"""Scanning helpers shared by the rule families.

Rules are pure functions of a ``DiffContext`` (SPEC §4.1): no I/O, no clock, no package
paths beyond what the sandbox already validated. Everything that could be a source of
crashes lives here so the family modules stay pattern tables plus documentation.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from pkgwatch.diff.files import split_lines
from pkgwatch.models import (
    DIFF_LINE_MAX_CHARS,
    DiffContext,
    DiffLineOp,
    FileView,
    Finding,
    Severity,
)

JS_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs")
PYPI_SUFFIXES = (".py",)
ROOT_MANIFEST = "package/package.json"

# PyPI build manifests: an install hook is declared here, not in a module. Depth is
# measured in directories under the extraction root, so a build file two directories
# down is still the package's own, not a vendored copy's.
PYPI_BUILD_FILES = ("setup.py", "pyproject.toml", "setup.cfg")

FULL_SCAN = "full"
PARTIAL_SCAN = "partial"


@dataclass(frozen=True)
class Pattern:
    """A named regular expression. The name is what lands in ``details["pattern"]``.

    ``capability`` groups patterns that detect the same power in different syntaxes (a
    ``require`` and an ESM ``import`` of one module). Old-tree presence is decided per
    group, so switching syntax does not read as a newly gained capability (SPEC §4.5).
    """

    name: str
    regex: re.Pattern[str]
    capability: str | None = None


def pattern(name: str, expression: str, *, capability: str | None = None) -> Pattern:
    return Pattern(name=name, regex=re.compile(expression), capability=capability)


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
    if any(
        len(line) > DIFF_LINE_MAX_CHARS
        for view in ctx.files_old.values()
        if view.is_text
        for line in split_lines(view.content)
    ):
        return PARTIAL_SCAN
    return FULL_SCAN


def _clipped_lines(view: FileView) -> Iterator[str]:
    """Old-tree lines bounded to the per-line cap, so one huge line cannot hang a regex."""
    for line in split_lines(view.content):
        yield line[:DIFF_LINE_MAX_CHARS]


def old_tree_has_capability(
    ctx: DiffContext, item: Pattern, suffixes: Sequence[str] = JS_SUFFIXES
) -> bool:
    """SPEC §4.5: "absent before" is decided against the whole old tree, not one file.

    Lines longer than the per-line cap are clipped before matching; ``old_tree_state``
    reports that as a partial scan so a clipped miss is never claimed as a full proof.
    """
    return any(
        item.regex.search(line)
        for view in text_views(ctx.files_old.values(), suffixes=suffixes)
        for line in _clipped_lines(view)
    )


def capability_findings(
    ctx: DiffContext,
    *,
    rule_id: str,
    rule_version: int,
    severity: Severity,
    patterns: Sequence[Pattern],
    suffixes: Sequence[str] = JS_SUFFIXES,
) -> list[Finding]:
    """Findings for added lines that introduce a capability the old tree lacked.

    One finding per matching line; the first pattern that matches a line wins, so a line
    that reads as two capabilities is reported once.
    """
    hits: list[tuple[int, str, str, Pattern]] = []
    for view in text_views(ctx.files_new.values(), suffixes=suffixes):
        for number, text in added_lines(view):
            for item in patterns:
                if item.regex.search(text):
                    hits.append((number, text, view.path, item))
                    break

    if not hits:
        return []
    scan_state = old_tree_state(ctx)
    groups: dict[str, list[Pattern]] = {}
    for item in patterns:
        groups.setdefault(item.capability or item.name, []).append(item)
    matched = {item.capability or item.name for _, _, _, item in hits}
    present = {
        key: any(old_tree_has_capability(ctx, member, suffixes) for member in groups[key])
        for key in matched
    }
    findings: list[Finding] = []
    for number, text, path, item in sorted(hits, key=lambda hit: (hit[2], hit[0])):
        if present[item.capability or item.name]:
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
                details={"pattern": item.name, "old_tree_scan": scan_state},
            )
        )
    return findings


def is_build_file(path: str) -> bool:
    """A PyPI build manifest of this package: a known name at depth <= 2."""
    if path.count("/") > 2:
        return False
    return path.rpartition("/")[2].lower() in PYPI_BUILD_FILES


def build_file_views(views: Iterable[FileView]) -> list[FileView]:
    """Text views of the package's own build manifests, in path order."""
    return [
        view
        for view in sorted(views, key=lambda item: item.path)
        if view.is_text and is_build_file(view.path)
    ]


def build_file_additions(ctx: DiffContext) -> list[tuple[str, int, str]]:
    """``(path, 1-based new line, text)`` for added lines of the new tree's build files."""
    return [
        (view.path, number, text)
        for view in build_file_views(ctx.files_new.values())
        for number, text in added_lines(view)
    ]


def old_build_files_have(ctx: DiffContext, item: Pattern) -> bool:
    """Whether an install-hook pattern already appeared in the old tree's build files."""
    return any(
        item.regex.search(line)
        for view in build_file_views(ctx.files_old.values())
        for line in _clipped_lines(view)
    )


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
