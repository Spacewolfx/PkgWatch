"""The shared scanner: bounded old-tree scanning and honest partial-scan reporting.

SPEC §4.5 decides "absent before" against the whole old tree. These tests pin the two
guarantees that keep that decision cheap and honest: a pattern with no new-tree hit never
scans the old tree, and a line too long to scan whole marks the result partial.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkgwatch.models import DIFF_LINE_MAX_CHARS, DiffContext, Ecosystem, Finding, Severity
from pkgwatch.rules import scan
from pkgwatch.rules.family2_capability import (
    fs_write_outside_package_added,
    js_child_process_added,
)
from tests.support.context import ctx_from_files


def test_no_old_tree_scan_when_the_new_tree_adds_no_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A pathological old line (thousands of unmatched write calls) must never be scanned
    # when no added line matches the pattern: the old-tree check is skipped entirely.
    bomb = b"fs.writeFile(" * 4000 + b"\n"
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.js": bomb},
        {"package/old.js": bomb, "package/new.js": b"var x = 1;\n"},
    )

    def _fail(*args: object, **kwargs: object) -> bool:
        raise AssertionError("old tree scanned despite no new-tree hit")

    monkeypatch.setattr(scan, "old_tree_has_capability", _fail)
    assert fs_write_outside_package_added(ctx) == []


def test_capability_beyond_the_line_cap_marks_the_scan_partial(tmp_path: Path) -> None:
    # The old line hides child_process past the per-line cap. Clipping means the scan
    # cannot prove absence, so the finding is emitted but honestly marked partial.
    pad = "x" * (DIFF_LINE_MAX_CHARS + 50)
    old_line = f'var pad = "{pad}"; const cp = require("child_process");\n'.encode()
    hit = b'const cp = require("child_process");\n'
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.js": old_line},
        {"package/old.js": old_line, "package/new.js": hit},
    )
    findings = js_child_process_added(ctx)
    assert len(findings) == 1
    assert findings[0].details["old_tree_scan"] == "partial"


def test_capability_within_the_line_cap_is_still_suppressed(tmp_path: Path) -> None:
    # Control: a capability inside the cap is found in the old tree, so it is not new and
    # the scan stays full. Clipping must not weaken ordinary detection.
    old_line = b'const cp = require("child_process");\n'
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.js": old_line},
        {"package/old.js": old_line, "package/new.js": old_line},
    )
    assert js_child_process_added(ctx) == []
    assert scan.old_tree_state(ctx) == "full"


def test_old_tree_has_capability_clips_long_lines(tmp_path: Path) -> None:
    pad = "x" * (DIFF_LINE_MAX_CHARS + 50)
    beyond = f'var pad = "{pad}"; const cp = require("child_process");\n'.encode()
    within = b'const cp = require("child_process");\n'
    pattern = scan.pattern(
        "child_process_require", r"""require\s*\(\s*["\x27]child_process["\x27]\s*\)"""
    )

    ctx_beyond = ctx_from_files(
        tmp_path, {"package/old.js": beyond}, {"package/new.js": b"var x = 1;\n"}
    )
    ctx_within = ctx_from_files(
        tmp_path, {"package/old.js": within}, {"package/new.js": b"var x = 1;\n"}
    )

    assert scan.old_tree_has_capability(ctx_beyond, pattern) is False
    assert scan.old_tree_has_capability(ctx_within, pattern) is True


def _capability(ctx: DiffContext, suffixes: tuple[str, ...], expression: str) -> list[Finding]:
    return scan.capability_findings(
        ctx,
        rule_id="TEST_CAPABILITY",
        rule_version=1,
        severity=Severity.HIGH,
        patterns=[scan.pattern("test_pattern", expression)],
        suffixes=suffixes,
    )


REQUIRE_CHILD_PROCESS = r"""require\s*\(\s*["\x27]child_process["\x27]\s*\)"""


def test_comment_only_lines_are_not_capabilities(tmp_path: Path) -> None:
    # A note that mentions a capability is not the package gaining it.
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.js": b"var x = 1;\n"},
        {
            "package/note.js": b'// require("child_process")\n',
            "package/block.js": b'/*\n * require("child_process")\n */\n',
        },
    )

    assert _capability(ctx, scan.JS_SUFFIXES, REQUIRE_CHILD_PROCESS) == []


def test_a_trailing_comment_is_ignored_but_the_code_is_not(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.js": b"var x = 1;\n"},
        {
            "package/note.js": b'var x = 1; // require("child_process")\n',
            "package/real.js": b'const cp = require("child_process"); // used\n',
        },
    )

    findings = _capability(ctx, scan.JS_SUFFIXES, REQUIRE_CHILD_PROCESS)
    assert [finding.path for finding in findings] == ["package/real.js"]


def test_a_comment_marker_inside_a_string_does_not_cut_the_line(tmp_path: Path) -> None:
    # "http://" must not be read as the start of a comment: the require after it counts.
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.js": b"var x = 1;\n"},
        {"package/net.js": b'var u = "http://x"; const cp = require("child_process");\n'},
    )

    assert len(_capability(ctx, scan.JS_SUFFIXES, REQUIRE_CHILD_PROCESS)) == 1


def test_a_python_comment_is_not_a_capability(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.py": b"x = 1\n"},
        {
            "package/note.py": b'# os.system("ls")\n',
            "package/real.py": b'os.system("ls")  # run\n',
        },
        ecosystem=Ecosystem.PYPI,
    )

    findings = _capability(ctx, scan.PYPI_SUFFIXES, r"os\.system\s*\(")
    assert [(finding.path, finding.line_start) for finding in findings] == [("real.py", 1)]


def test_a_comment_in_the_old_tree_does_not_hide_a_new_capability(tmp_path: Path) -> None:
    # The old-tree check must ignore comments the same way, or a note in the previous
    # version would suppress the real addition in the new one.
    old_line = b'// note: require("child_process")\n'
    ctx = ctx_from_files(
        tmp_path,
        {"package/old.js": old_line},
        {"package/old.js": old_line, "package/new.js": b'const cp = require("child_process");\n'},
    )

    findings = _capability(ctx, scan.JS_SUFFIXES, REQUIRE_CHILD_PROCESS)
    assert [finding.path for finding in findings] == ["package/new.js"]
