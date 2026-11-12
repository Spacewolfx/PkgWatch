"""File-level diff of two extraction manifests.

Nothing here parses source: the differ classifies by path and SHA-256, reads text for
the rules, and records per-file read failures as ``ParseError`` instead of raising.
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from pkgwatch.diff import build_diff_context
from pkgwatch.models import (
    ChangeType,
    DiffContext,
    DiffLineOp,
    Ecosystem,
    FileRole,
    ParseErrorKind,
    SandboxLimits,
)
from tests.support.archives import Entry
from tests.support.trees import extract_tree

PUBLISHED = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def build(
    tmp_path: Path,
    old_entries: list[Entry],
    new_entries: list[Entry],
    limits: SandboxLimits | None = None,
) -> DiffContext:
    case = Path(tempfile.mkdtemp(dir=tmp_path))
    old = extract_tree(case, "old", old_entries, limits)
    new = extract_tree(case, "new", new_entries, limits)
    return build_diff_context(
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="1.1.0",
        published_at=PUBLISHED,
        old=old,
        new=new,
        limits=limits or SandboxLimits(),
    )


def types(ctx: DiffContext) -> dict[str, ChangeType]:
    return {(c.path_new or c.path_old or ""): c.change_type for c in ctx.changes}


def test_added_removed_modified_unchanged_are_classified_by_path_and_hash(
    tmp_path: Path,
) -> None:
    ctx = build(
        tmp_path,
        [
            Entry("package/keep.js", b"same\n"),
            Entry("package/drop.js", b"gone\n"),
            Entry("package/edit.js", b"before\n"),
        ],
        [
            Entry("package/keep.js", b"same\n"),
            Entry("package/edit.js", b"after\n"),
            Entry("package/add.js", b"new\n"),
        ],
    )
    assert types(ctx) == {
        "package/add.js": ChangeType.ADDED,
        "package/drop.js": ChangeType.REMOVED,
        "package/edit.js": ChangeType.MODIFIED,
        "package/keep.js": ChangeType.UNCHANGED,
    }


def test_changes_are_sorted_by_path_and_repeatable(tmp_path: Path) -> None:
    entries_old = [Entry("package/b.js", b"1\n"), Entry("package/a.js", b"2\n")]
    entries_new = [Entry("package/b.js", b"3\n"), Entry("package/a.js", b"4\n")]
    first = build(tmp_path, entries_old, entries_new)
    second = build(tmp_path, entries_old, entries_new)
    assert [c.path_new for c in first.changes] == ["package/a.js", "package/b.js"]
    assert first.model_dump() == second.model_dump()


def test_sizes_and_hashes_are_recorded(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package/edit.js", b"before\n")],
        [Entry("package/edit.js", b"afterly\n")],
    )
    change = ctx.changes[0]
    assert (change.size_old, change.size_new) == (7, 8)
    assert change.sha256_old
    assert change.sha256_new
    assert change.sha256_old != change.sha256_new


def test_modified_files_expose_line_diffs_with_1_based_numbers(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package/edit.js", b"alpha\nbeta\ngamma\n")],
        [Entry("package/edit.js", b"alpha\nBETA changed\ngamma\nextra\n")],
    )
    view = ctx.files_new["package/edit.js"]
    assert [(line.op, line.line_old, line.line_new) for line in view.diff_lines] == [
        (DiffLineOp.CTX, 1, 1),
        (DiffLineOp.DEL, 2, None),
        (DiffLineOp.ADD, None, 2),
        (DiffLineOp.CTX, 3, 3),
        (DiffLineOp.ADD, None, 4),
    ]
    change = ctx.changes[0]
    assert (change.lines_added, change.lines_removed) == (2, 1)


def test_added_files_are_all_add_lines(tmp_path: Path) -> None:
    ctx = build(tmp_path, [], [Entry("package/new.js", b"one\ntwo\n")])
    view = ctx.files_new["package/new.js"]
    assert [line.op for line in view.diff_lines] == [DiffLineOp.ADD, DiffLineOp.ADD]
    assert [line.line_new for line in view.diff_lines] == [1, 2]


def test_removed_files_are_all_del_lines_against_the_old_view(tmp_path: Path) -> None:
    ctx = build(tmp_path, [Entry("package/gone.js", b"one\ntwo\n")], [])
    assert "package/gone.js" not in ctx.files_new
    view = ctx.files_old["package/gone.js"]
    assert [line.op for line in view.diff_lines] == [DiffLineOp.DEL, DiffLineOp.DEL]
    assert [line.line_old for line in view.diff_lines] == [1, 2]


def test_unchanged_files_leave_the_new_input_but_stay_readable_in_old(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package/keep.js", b"same\n"), Entry("package/edit.js", b"a\n")],
        [Entry("package/keep.js", b"same\n"), Entry("package/edit.js", b"b\n")],
    )
    assert "package/keep.js" not in ctx.files_new
    assert "package/keep.js" in ctx.files_old
    assert types(ctx)["package/keep.js"] is ChangeType.UNCHANGED


def test_invalid_utf8_is_decoded_with_replacement(tmp_path: Path) -> None:
    ctx = build(
        tmp_path, [Entry("package/x.js", b"prefix\n")], [Entry("package/x.js", b"\xff\xfe bad\n")]
    )
    view = ctx.files_new["package/x.js"]
    assert "\ufffd" in view.content
    assert view.is_text is True


def test_text_over_the_scan_cap_is_truncated_and_flagged(tmp_path: Path) -> None:
    limits = SandboxLimits(text_scan_bytes=8)
    ctx = build(
        tmp_path,
        [Entry("package/x.js", b"short\n", mode=0o644)],
        [Entry("package/x.js", b"0123456789abcdefghijklmnop\n")],
        limits,
    )
    view = ctx.files_new["package/x.js"]
    assert view.content == "01234567"
    assert view.truncated is True
    assert view.size == 27


def test_binary_content_is_flagged_and_carries_no_text(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package/blob.bin", b"\x00\x01\x02\x03")],
        [Entry("package/blob.bin", b"\x00\x01\x02\x04")],
    )
    assert types(ctx)["package/blob.bin"] is ChangeType.BINARY
    change = next(c for c in ctx.changes if c.path_new == "package/blob.bin")
    assert change.is_text is False
    assert change.role is FileRole.BINARY
    assert "package/blob.bin" not in ctx.files_new


def test_mode_only_change_is_reported_without_line_diff(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package/tool.js", b"run\n", mode=0o644)],
        [Entry("package/tool.js", b"run\n", mode=0o755)],
    )
    change = ctx.changes[0]
    assert change.change_type is ChangeType.MODE_ONLY
    assert change.mode_new == 0o755
    assert (change.lines_added, change.lines_removed) == (0, 0)


def test_unicode_line_separators_do_not_split_a_physical_line(tmp_path: Path) -> None:
    # \u2028 (LINE SEPARATOR) inside a string is not a line break: only \n delimits
    # lines, so reported line numbers match the file a consumer's editor would show.
    raw = 'var a = "x\u2028y";\nvar b = 2;\n'.encode("utf-8")
    ctx = build(tmp_path, [], [Entry("package/a.js", raw)])
    view = ctx.files_new["package/a.js"]
    added = [line.line_new for line in view.diff_lines if line.op is DiffLineOp.ADD]
    assert added == [1, 2]


def test_crlf_line_endings_count_as_one_break(tmp_path: Path) -> None:
    ctx = build(tmp_path, [], [Entry("package/a.js", b"var a = 1;\r\nvar b = 2;\r\n")])
    view = ctx.files_new["package/a.js"]
    added = [(line.line_new, line.text) for line in view.diff_lines if line.op is DiffLineOp.ADD]
    assert added == [(1, "var a = 1;"), (2, "var b = 2;")]


def test_nested_archives_are_reported_not_read(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package/inner.tgz", b"old-bytes")],
        [Entry("package/inner.tgz", b"new-bytes")],
    )
    assert types(ctx)["package/inner.tgz"] is ChangeType.NESTED_ARCHIVE
    assert "package/inner.tgz" not in ctx.files_new


def test_symlink_entries_are_reported_without_content(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [
            Entry("package/index.js", b"a\n"),
            Entry("package/link.js", kind="symlink", linkname="index.js"),
        ],
        [
            Entry("package/index.js", b"b\n"),
            Entry("package/link.js", kind="symlink", linkname="index.js"),
        ],
    )
    change = next(c for c in ctx.changes if (c.path_new or c.path_old) == "package/link.js")
    assert change.change_type is ChangeType.UNCHANGED
    assert change.is_text is False
    assert "package/link.js" not in ctx.files_new
    assert types(ctx)["package/index.js"] is ChangeType.MODIFIED


def test_directory_entries_are_not_file_changes(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package", kind="dir"), Entry("package/index.js", b"a\n")],
        [Entry("package", kind="dir"), Entry("package/index.js", b"b\n")],
    )
    assert "package" not in types(ctx)


def test_a_file_missing_on_disk_becomes_a_parse_error_not_a_crash(tmp_path: Path) -> None:
    case = Path(tempfile.mkdtemp(dir=tmp_path))
    old = extract_tree(case, "old", [Entry("package/index.js", b"a\n")])
    new = extract_tree(case, "new", [Entry("package/index.js", b"b\n")])
    (new.root / "package" / "index.js").unlink()

    ctx = build_diff_context(
        ecosystem=Ecosystem.NPM,
        package_name="demo-pkg",
        old_version="1.0.0",
        new_version="1.1.0",
        published_at=PUBLISHED,
        old=old,
        new=new,
        limits=SandboxLimits(),
    )
    assert [error.path for error in ctx.parse_errors] == ["package/index.js"]
    assert ctx.parse_errors[0].kind is ParseErrorKind.READ
    assert "package/index.js" not in ctx.files_new
    assert types(ctx)["package/index.js"] is ChangeType.MODIFIED


def test_context_view_budget_marks_the_context_incomplete(tmp_path: Path) -> None:
    # Each tree fits the sandbox cap on its own; the two together do not, so the
    # differ stops reading once the shared view budget is spent.
    limits = SandboxLimits(max_total_uncompressed_bytes=16)
    ctx = build(
        tmp_path,
        [Entry("package/a.js", b"a" * 10 + b"\n")],
        [
            Entry("package/a.js", b"b" * 10 + b"\n"),
            Entry("package/c.js", b"c\n"),
        ],
        limits,
    )
    assert ctx.views_incomplete is True
    assert any(error.kind is ParseErrorKind.BUDGET for error in ctx.parse_errors)
    assert "package/a.js" not in ctx.files_new
    assert "package/c.js" in ctx.files_new


def test_first_release_treats_every_file_as_added(tmp_path: Path) -> None:
    ctx = build(tmp_path, [], [Entry("package/index.js", b"a\n"), Entry("README.md", b"hi\n")])
    assert set(types(ctx).values()) == {ChangeType.ADDED}
    assert set(ctx.files_new) == {"README.md", "package/index.js"}
    assert ctx.files_old == {}


def test_role_classification_uses_path_heuristics(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [],
        [
            Entry("package/package.json", b"{}\n"),
            Entry("package/lib/index.js", b"// code\n"),
            Entry("package/test/index.test.js", b"// test\n"),
            Entry("README.md", b"# doc\n"),
            Entry("package/package-lock.json", b"{}\n"),
            Entry("node_modules/dep/index.js", b"// vendored\n"),
            Entry("package/data.csv", b"a,b\n"),
        ],
    )
    roles = {(c.path_new or ""): c.role for c in ctx.changes}
    assert roles["package/package.json"] is FileRole.MANIFEST
    assert roles["package/lib/index.js"] is FileRole.SOURCE
    assert roles["package/test/index.test.js"] is FileRole.TEST
    assert roles["README.md"] is FileRole.DOC
    assert roles["package/package-lock.json"] is FileRole.LOCKFILE
    assert roles["node_modules/dep/index.js"] is FileRole.VENDOR
    assert roles["package/data.csv"] is FileRole.OTHER


def test_renames_are_reported_as_remove_plus_add_in_m2(tmp_path: Path) -> None:
    ctx = build(
        tmp_path,
        [Entry("package/old_name.js", b"identical content\n")],
        [Entry("package/new_name.js", b"identical content\n")],
    )
    assert types(ctx) == {
        "package/new_name.js": ChangeType.ADDED,
        "package/old_name.js": ChangeType.REMOVED,
    }


def _build_pypi(
    tmp_path: Path,
    old_entries: list[Entry],
    new_entries: list[Entry],
) -> DiffContext:
    case = Path(tempfile.mkdtemp(dir=tmp_path))
    old = extract_tree(case, "old", old_entries)
    new = extract_tree(case, "new", new_entries)
    return build_diff_context(
        ecosystem=Ecosystem.PYPI,
        package_name="requests",
        old_version="2.31.0",
        new_version="2.32.0",
        published_at=PUBLISHED,
        old=old,
        new=new,
        limits=SandboxLimits(),
    )


def test_pypi_sdist_version_roots_are_stripped_before_diffing(tmp_path: Path) -> None:
    """An sdist root {name}-{version}/ differs per version; diff on the path inside it.

    Regression for the silent no-op bug: without stripping, requests-2.31.0/... and
    requests-2.32.0/... share no path, so everything looks added+removed and a version
    bump reports modified=0.
    """
    ctx = _build_pypi(
        tmp_path,
        [
            Entry("requests-2.31.0/PKG-INFO", b"Metadata-Version: 2.1\nVersion: 2.31.0\n"),
            Entry("requests-2.31.0/requests/utils.py", b"VALUE = 1\n"),
            Entry("requests-2.31.0/requests/keep.py", b"SAME = 1\n"),
        ],
        [
            Entry("requests-2.32.0/PKG-INFO", b"Metadata-Version: 2.1\nVersion: 2.32.0\n"),
            Entry("requests-2.32.0/requests/utils.py", b"VALUE = 2\n"),
            Entry("requests-2.32.0/requests/keep.py", b"SAME = 1\n"),
        ],
    )
    assert types(ctx) == {
        "PKG-INFO": ChangeType.MODIFIED,
        "requests/utils.py": ChangeType.MODIFIED,
        "requests/keep.py": ChangeType.UNCHANGED,
    }
