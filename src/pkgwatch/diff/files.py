"""File-level comparison of two extraction manifests.

This is the boundary between the sandbox and the rule engine: it decides what changed by
path and SHA-256, decodes text for the rules, and turns anything it cannot read into a
``ParseError`` row instead of an exception. It does not parse source, build syntax trees, or
run anything — a downloaded file is hostile input, and here it is only ever bytes and lines.

Two caps keep the context bounded, because a package can claim gigabytes of text:
``text_scan_bytes`` truncates one file's view, and ``max_total_uncompressed_bytes`` is a
second, shared allowance for building views across *both* trees. A file that cannot fit is
skipped and recorded, so ``views_incomplete`` states the gap instead of the rules silently
reasoning from less than the truth.

Rename detection is deliberately absent: a moved file is one REMOVED row plus one ADDED row,
which is honest and needs no similarity threshold to tune.
"""

from __future__ import annotations

import difflib
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from pkgwatch.models import (
    DIFF_LINE_MAX_CHARS,
    EVIDENCE_MAX_CHARS,
    ChangeType,
    DiffContext,
    DiffLine,
    DiffLineOp,
    Ecosystem,
    ExtractionResult,
    FileChange,
    FileRole,
    FileView,
    ManifestEntry,
    ManifestKind,
    ObfuscationLimits,
    ParseError,
    ParseErrorKind,
    SandboxLimits,
)
from pkgwatch.sandbox.names import within_root

ARCHIVE_SUFFIXES = frozenset(
    {".tgz", ".gz", ".bz2", ".xz", ".zip", ".tar", ".whl", ".gem", ".jar", ".crate"}
)
MANIFEST_NAMES = frozenset(
    {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "cargo.toml"}
)
LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "cargo.lock",
        "poetry.lock",
        "uv.lock",
        "requirements.txt",
    }
)
SOURCE_SUFFIXES = frozenset(
    {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".py",
        ".rs",
        ".rb",
        ".go",
        ".sh",
        ".bash",
        ".ps1",
    }
)
DOC_SUFFIXES = frozenset({".md", ".rst", ".txt", ".adoc", ".markdown"})
DOC_NAMES = frozenset({"license", "licence", "copying", "readme", "changelog", "notice"})
TEST_DIRS = frozenset({"test", "tests", "spec", "specs", "__tests__", "example", "examples"})
VENDOR_DIRS = frozenset({"node_modules", "vendor", "site-packages", "third_party", ".yarn"})
TEST_SUFFIXES = (".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.py", ".bats")
BINARY_SNIFF_BYTES = 8192
_NO_TEXT_VIEWS = frozenset({ChangeType.BINARY, ChangeType.NESTED_ARCHIVE})


def build_diff_context(
    *,
    ecosystem: Ecosystem,
    package_name: str,
    old_version: str,
    new_version: str,
    published_at: datetime,
    old: ExtractionResult,
    new: ExtractionResult,
    limits: SandboxLimits,
    metadata_before: Mapping[str, Any] | None = None,
    metadata_after: Mapping[str, Any] | None = None,
    obfuscation: ObfuscationLimits | None = None,
) -> DiffContext:
    """Compare two extracted trees into the one object a rule is allowed to read."""
    if ecosystem is Ecosystem.PYPI:
        # An sdist unpacks under a single {name}-{version}/ root that differs per
        # version; re-root both trees so the same inner path compares to itself.
        old = _re_root(old)
        new = _re_root(new)
    old_entries = _by_path(old.entries)
    new_entries = _by_path(new.entries)
    budget = _Budget(limits.max_total_uncompressed_bytes)
    changes: list[FileChange] = []
    files_old: dict[str, FileView] = {}
    files_new: dict[str, FileView] = {}
    parse_errors: list[ParseError] = []

    for path in sorted(set(old_entries) | set(new_entries)):
        entry_old = old_entries.get(path)
        entry_new = new_entries.get(path)

        if _is_archive(path, entry_old, entry_new):
            changes.append(_change(path, entry_old, entry_new, ChangeType.NESTED_ARCHIVE, ()))
            continue

        raw_old = _read(old.root, entry_old, limits, budget, parse_errors)
        raw_new = _read(new.root, entry_new, limits, budget, parse_errors)
        change_type = _classify(entry_old, entry_new, raw_old, raw_new)
        diff_lines = _diff_for(change_type, raw_old, raw_new)
        changes.append(_change(path, entry_old, entry_new, change_type, diff_lines))

        if change_type not in _NO_TEXT_VIEWS:
            if change_type is not ChangeType.ADDED:
                view_old = _view(entry_old, raw_old, diff_lines)
                if view_old is not None:
                    files_old[path] = view_old
            if change_type not in {ChangeType.REMOVED, ChangeType.UNCHANGED, ChangeType.MODE_ONLY}:
                view_new = _view(entry_new, raw_new, diff_lines)
                if view_new is not None:
                    files_new[path] = view_new

    return DiffContext(
        ecosystem=ecosystem,
        package_name=package_name,
        old_version=old_version,
        new_version=new_version,
        published_at=published_at,
        changes=tuple(changes),
        files_new=files_new,
        files_old=files_old,
        metadata_before=dict(metadata_before or {}),
        metadata_after=dict(metadata_after or {}),
        parse_errors=tuple(parse_errors),
        limits=limits,
        obfuscation=obfuscation or ObfuscationLimits(),
        views_incomplete=bool(parse_errors),
    )


def _by_path(entries: Sequence[ManifestEntry]) -> dict[str, ManifestEntry]:
    """Directory rows carry no content, so they are not file changes."""
    return {entry.path: entry for entry in entries if entry.kind is not ManifestKind.DIR}


def _common_top_dir(entries: Sequence[ManifestEntry]) -> str | None:
    """The single top-level directory every file sits under (an sdist root), or None.

    A wheel's files live at the archive root, so there is no single top directory and
    nothing is stripped. Requiring *every* file to be strictly under the one directory
    keeps a malformed archive (a file at the root beside a directory) from being
    mis-re-rooted.
    """
    tops: set[str] = set()
    for entry in entries:
        if entry.kind is ManifestKind.DIR:
            continue
        tops.add(entry.path.split("/", 1)[0])
        if len(tops) > 1:
            return None
    if not tops:
        return None
    top = tops.pop()
    prefix = top + "/"
    if any(
        entry.kind is not ManifestKind.DIR and not entry.path.startswith(prefix)
        for entry in entries
    ):
        return None
    return top


def _re_root(result: ExtractionResult) -> ExtractionResult:
    """Re-root a tree on its single top directory, or return it unchanged."""
    top = _common_top_dir(result.entries)
    if top is None:
        return result
    prefix = top + "/"
    entries = tuple(
        entry.model_copy(update={"path": entry.path[len(prefix) :]})
        for entry in result.entries
        if entry.path != top
    )
    return result.model_copy(update={"root": result.root / top, "entries": entries})


class _Budget:
    """Shared allowance for reading file bodies into views, in uncompressed bytes."""

    def __init__(self, limit: int) -> None:
        self.remaining = limit

    def take(self, needed: int) -> bool:
        if needed > self.remaining:
            return False
        self.remaining -= needed
        return True


def _is_archive(
    path: str, entry_old: ManifestEntry | None, entry_new: ManifestEntry | None
) -> bool:
    if any(
        entry is not None and entry.kind is ManifestKind.NESTED_ARCHIVE
        for entry in (entry_old, entry_new)
    ):
        return True
    return PurePosixPath(path).suffix.lower() in ARCHIVE_SUFFIXES


def _is_link(entry: ManifestEntry | None) -> bool:
    return entry is not None and entry.kind is ManifestKind.SYMLINK


def _read(
    root: Path,
    entry: ManifestEntry | None,
    limits: SandboxLimits,
    budget: _Budget,
    parse_errors: list[ParseError],
) -> bytes | None:
    """Bytes of one file, capped at ``text_scan_bytes``; ``None`` with a recorded reason."""
    if entry is None or _is_link(entry) or entry.sha256 is None:
        return None
    path = entry.path
    needed = min(entry.size, limits.text_scan_bytes)
    if not budget.take(needed):
        parse_errors.append(
            ParseError(
                path=path,
                kind=ParseErrorKind.BUDGET,
                detail=(
                    f"view allowance of {limits.max_total_uncompressed_bytes} bytes was spent "
                    f"before this {needed}-byte file"
                ),
            )
        )
        return None
    try:
        resolved = within_root(root, entry.path)
        with resolved.open("rb") as handle:
            return handle.read(limits.text_scan_bytes)
    except (OSError, ValueError) as exc:
        parse_errors.append(
            ParseError(
                path=path,
                kind=ParseErrorKind.READ,
                detail=f"{type(exc).__name__}: {exc}"[:EVIDENCE_MAX_CHARS],
            )
        )
        return None


def _is_binary(raw: bytes | None) -> bool:
    return raw is not None and b"\x00" in raw[:BINARY_SNIFF_BYTES]


def _classify(
    entry_old: ManifestEntry | None,
    entry_new: ManifestEntry | None,
    raw_old: bytes | None,
    raw_new: bytes | None,
) -> ChangeType:
    if entry_old is None:
        return ChangeType.ADDED
    if entry_new is None:
        return ChangeType.REMOVED
    if _is_link(entry_old) or _is_link(entry_new):
        same = entry_old.link_target == entry_new.link_target and entry_old.mode == entry_new.mode
        return ChangeType.UNCHANGED if same else ChangeType.MODIFIED
    if _is_binary(raw_old) or _is_binary(raw_new):
        return ChangeType.BINARY
    if entry_old.sha256 is not None and entry_old.sha256 == entry_new.sha256:
        if entry_old.mode == entry_new.mode:
            return ChangeType.UNCHANGED
        return ChangeType.MODE_ONLY
    return ChangeType.MODIFIED


def _diff_for(
    change_type: ChangeType, raw_old: bytes | None, raw_new: bytes | None
) -> tuple[DiffLine, ...]:
    if change_type is ChangeType.ADDED:
        return _one_sided(raw_new, DiffLineOp.ADD)
    if change_type is ChangeType.REMOVED:
        return _one_sided(raw_old, DiffLineOp.DEL)
    if change_type is ChangeType.MODIFIED:
        return _two_sided(raw_old, raw_new)
    return ()


def _one_sided(raw: bytes | None, op: DiffLineOp) -> tuple[DiffLine, ...]:
    lines = _lines(raw)
    if lines is None:
        return ()
    if op is DiffLineOp.ADD:
        return tuple(
            DiffLine(op=op, text=_clip(text), line_new=number)
            for number, text in enumerate(lines, start=1)
        )
    return tuple(
        DiffLine(op=op, text=_clip(text), line_old=number)
        for number, text in enumerate(lines, start=1)
    )


def _two_sided(raw_old: bytes | None, raw_new: bytes | None) -> tuple[DiffLine, ...]:
    old_lines = _lines(raw_old)
    new_lines = _lines(raw_new)
    if old_lines is None or new_lines is None:
        return ()
    lines: list[DiffLine] = []
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                lines.append(
                    DiffLine(
                        op=DiffLineOp.CTX,
                        text=_clip(old_lines[i1 + offset]),
                        line_old=i1 + offset + 1,
                        line_new=j1 + offset + 1,
                    )
                )
            continue
        if tag in {"delete", "replace"}:
            for number in range(i1, i2):
                lines.append(
                    DiffLine(op=DiffLineOp.DEL, text=_clip(old_lines[number]), line_old=number + 1)
                )
        if tag in {"insert", "replace"}:
            for number in range(j1, j2):
                lines.append(
                    DiffLine(op=DiffLineOp.ADD, text=_clip(new_lines[number]), line_new=number + 1)
                )
    return tuple(lines)


def split_lines(text: str) -> list[str]:
    """Split on ``\\n`` only, treating CRLF as one break and a final newline as a terminator.

    ``str.splitlines`` also breaks on \\v, \\f, \\x85, \\u2028 and \\u2029, which appear inside
    string literals; counting those as lines misaligns every reported line number against
    the file a consumer's editor shows. A trailing carriage return is dropped so CRLF and
    LF files produce identical line text.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _lines(raw: bytes | None) -> list[str] | None:
    return None if raw is None else split_lines(raw.decode("utf-8", errors="replace"))


def _clip(text: str) -> str:
    return text if len(text) <= DIFF_LINE_MAX_CHARS else text[:DIFF_LINE_MAX_CHARS]


def _view(
    entry: ManifestEntry | None, raw: bytes | None, diff_lines: Sequence[DiffLine]
) -> FileView | None:
    if entry is None or raw is None or entry.sha256 is None or _is_binary(raw):
        return None
    return FileView(
        path=entry.path,
        content=raw.decode("utf-8", errors="replace"),
        is_text=True,
        size=entry.size,
        sha256=entry.sha256,
        truncated=len(raw) < entry.size,
        diff_lines=tuple(diff_lines),
    )


def _change(
    path: str,
    entry_old: ManifestEntry | None,
    entry_new: ManifestEntry | None,
    change_type: ChangeType,
    diff_lines: Sequence[DiffLine],
) -> FileChange:
    textual = change_type not in _NO_TEXT_VIEWS and not (_is_link(entry_old) or _is_link(entry_new))
    return FileChange(
        path_old=None if entry_old is None else path,
        path_new=None if entry_new is None else path,
        change_type=change_type,
        size_old=None if entry_old is None else entry_old.size,
        size_new=None if entry_new is None else entry_new.size,
        sha256_old=None if entry_old is None else entry_old.sha256,
        sha256_new=None if entry_new is None else entry_new.sha256,
        lines_added=sum(1 for line in diff_lines if line.op is DiffLineOp.ADD),
        lines_removed=sum(1 for line in diff_lines if line.op is DiffLineOp.DEL),
        mode_new=None if entry_new is None else entry_new.mode,
        is_text=textual,
        role=_role(path, change_type),
    )


def _role(path: str, change_type: ChangeType) -> FileRole:
    if change_type is ChangeType.BINARY:
        return FileRole.BINARY
    if change_type is ChangeType.NESTED_ARCHIVE:
        return FileRole.OTHER
    parts = [part.lower() for part in PurePosixPath(path).parts]
    name = parts[-1]
    if any(part in VENDOR_DIRS for part in parts[:-1]):
        return FileRole.VENDOR
    if any(part in TEST_DIRS for part in parts[:-1]) or name.endswith(TEST_SUFFIXES):
        return FileRole.TEST
    if name in MANIFEST_NAMES:
        return FileRole.MANIFEST
    if name in LOCKFILE_NAMES:
        return FileRole.LOCKFILE
    suffix = PurePosixPath(name).suffix.lower()
    if suffix in DOC_SUFFIXES or (not suffix and name in DOC_NAMES):
        return FileRole.DOC
    if suffix in SOURCE_SUFFIXES:
        return FileRole.SOURCE
    return FileRole.OTHER
