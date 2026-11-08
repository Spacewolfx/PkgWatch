"""Records introduced with M2: diff context, rule families, stored rows.

These shapes cross module boundaries, so the invariants the pipeline leans on (diff
line link direction, view/change consistency, no content on non-text views) are
enforced here instead of being re-checked in every consumer.
"""

from __future__ import annotations

import datetime as dt

import pytest
from pydantic import ValidationError

from pkgwatch.models import (
    ChangeType,
    DiffContext,
    DiffLine,
    DiffLineOp,
    Ecosystem,
    FileChange,
    FileView,
    ParseError,
    ParseErrorKind,
    ReleaseStatus,
    RuleFamily,
    SandboxLimits,
    StoredRelease,
    WatchEntry,
)
from tests.support.records import make_release

UTC = dt.UTC


def _moment() -> dt.datetime:
    return dt.datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def _view(path: str = "package/index.js") -> FileView:
    return FileView(
        path=path,
        content="require('child_process')\n",
        is_text=True,
        size=28,
        sha256="0" * 64,
        truncated=False,
        diff_lines=(DiffLine(op=DiffLineOp.ADD, text="require('child_process')", line_new=1),),
    )


def _context(**overrides: object) -> DiffContext:
    base: dict[str, object] = {
        "ecosystem": Ecosystem.NPM,
        "package_name": "demo-pkg",
        "old_version": "1.0.0",
        "new_version": "1.1.0",
        "published_at": _moment(),
        "changes": (
            FileChange(
                path_new="package/index.js",
                change_type=ChangeType.ADDED,
                size_new=28,
                sha256_new="0" * 64,
                lines_added=1,
            ),
        ),
        "files_new": {"package/index.js": _view()},
        "files_old": {},
        "metadata_before": {},
        "metadata_after": {},
        "parse_errors": (),
        "limits": SandboxLimits(),
    }
    base.update(overrides)
    return DiffContext.model_validate(base)


def test_diff_context_defaults() -> None:
    ctx = _context()
    assert ctx.views_incomplete is False
    assert ctx.ecosystem is Ecosystem.NPM
    assert ctx.limits.text_scan_bytes == 2 * 1024 * 1024


def test_diff_context_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError, match="Extra inputs"):
        _context(surprise=1)


def test_added_line_requires_new_line_number() -> None:
    with pytest.raises(ValidationError, match="line_new"):
        DiffLine(op=DiffLineOp.ADD, text="x")


def test_removed_line_requires_old_line_number() -> None:
    with pytest.raises(ValidationError, match="line_old"):
        DiffLine(op=DiffLineOp.DEL, text="x", line_new=1)


def test_context_line_requires_both_numbers() -> None:
    with pytest.raises(ValidationError, match="line_old"):
        DiffLine(op=DiffLineOp.CTX, text="x", line_new=3)


def test_diff_line_text_is_capped() -> None:
    with pytest.raises(ValidationError, match="at most"):
        DiffLine(op=DiffLineOp.ADD, text="x" * 4000, line_new=1)


def test_binary_view_may_not_carry_content() -> None:
    with pytest.raises(ValidationError, match="is_text"):
        FileView(
            path="package/blob.bin",
            content="NUL text",
            is_text=False,
            size=4,
            sha256="1" * 64,
            truncated=False,
            diff_lines=(),
        )


def test_file_view_sha256_must_be_hex() -> None:
    with pytest.raises(ValidationError, match="hex"):
        FileView(
            path="package/index.js",
            content="",
            is_text=False,
            size=0,
            sha256="zz",
            truncated=False,
            diff_lines=(),
        )


def test_views_must_be_referenced_by_a_change() -> None:
    with pytest.raises(ValidationError, match="no FileChange"):
        _context(files_old={"package/gone.js": _view("package/gone.js")})


def test_view_key_and_view_path_must_agree() -> None:
    with pytest.raises(ValidationError, match="disagrees"):
        _context(files_new={"package/index.js": _view("package/elsewhere.js")})


def test_parse_error_detail_is_capped() -> None:
    error = ParseError(path="package/x.js", kind=ParseErrorKind.READ, detail="x" * 500)
    assert len(error.detail) <= 200
    assert error.detail.endswith("…")


def test_rule_family_values_are_stable() -> None:
    assert [family.value for family in RuleFamily] == [
        "lifecycle_scripts",
        "dangerous_capability",
        "obfuscation",
        "metadata",
    ]


def test_release_status_pipeline_order() -> None:
    assert [status.value for status in ReleaseStatus] == [
        "pending",
        "fetched",
        "extracted",
        "diffed",
        "scored",
        "exported",
    ]


def test_stored_release_defaults_to_pending_and_complete() -> None:
    stored = StoredRelease(release=make_release())
    assert stored.status is ReleaseStatus.PENDING
    assert stored.stage_error is None
    assert stored.analysis_incomplete is False


def test_stored_release_stage_error_is_capped() -> None:
    stored = StoredRelease(release=make_release(), stage_error="x" * 900)
    assert stored.stage_error is not None
    assert len(stored.stage_error) <= 500


def test_watch_entry_requires_aware_timestamp() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        WatchEntry(
            ecosystem=Ecosystem.NPM,
            package_name="demo-pkg",
            added_at=dt.datetime(2026, 11, 5, 12, 0),
        )
