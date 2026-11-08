"""Family 2 (new dangerous capabilities, npm).

Matching is on ADDED lines only; AST diffing is M4, so every rule here states the
blind spots that line matching cannot see.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from pkgwatch.models import DiffContext, Ecosystem, Finding, RuleFamily, SandboxLimits, Severity
from pkgwatch.rules import RULES
from pkgwatch.rules.family2_capability import (
    DYNAMIC_EVAL_ADDED,
    ENV_ENUMERATION_ADDED,
    FS_WRITE_OUTSIDE_PACKAGE_ADDED,
    JS_CHILD_PROCESS_ADDED,
    NET_ACCESS_ADDED,
    dynamic_eval_added,
    env_enumeration_added,
    fs_write_outside_package_added,
    js_child_process_added,
    net_access_added,
)
from tests.support.context import ctx_from_files
from tests.support.fixtures import rule_context

BASE = {"package/base.js": b"module.exports = 1;\n"}

DETECTIONS: list[tuple[str, Callable[[DiffContext], list[Finding]], Severity, str, str]] = [
    (
        JS_CHILD_PROCESS_ADDED,
        js_child_process_added,
        Severity.HIGH,
        'const cp = require("child_process");\n',
        "child_process_require",
    ),
    (
        DYNAMIC_EVAL_ADDED,
        dynamic_eval_added,
        Severity.HIGH,
        'var fn = eval("1 + 1");\n',
        "eval_call",
    ),
    (
        NET_ACCESS_ADDED,
        net_access_added,
        Severity.MEDIUM,
        'const https = require("https");\n',
        "https_require",
    ),
    (
        FS_WRITE_OUTSIDE_PACKAGE_ADDED,
        fs_write_outside_package_added,
        Severity.MEDIUM,
        'fs.writeFileSync(path.join(cwd, "..", "startup.js"), text);\n',
        "write_escaping_package_dir",
    ),
    (
        ENV_ENUMERATION_ADDED,
        env_enumeration_added,
        Severity.LOW,
        "var names = Object.keys(process.env);\n",
        "enumerate_process_env",
    ),
]

NEAR_MISSES: list[tuple[str, Callable[[DiffContext], list[Finding]], str]] = [
    (JS_CHILD_PROCESS_ADDED, js_child_process_added, "var runner = require('util');\n"),
    (
        DYNAMIC_EVAL_ADDED,
        dynamic_eval_added,
        "var total = parseInt(value, 10); // evaluate later\n",
    ),
    (NET_ACCESS_ADDED, net_access_added, 'var parsed = url.parse("local:8080");\n'),
    (
        FS_WRITE_OUTSIDE_PACKAGE_ADDED,
        fs_write_outside_package_added,
        'fs.writeFileSync(path.join(cwd, "inside.js"), text);\n',
    ),
    (ENV_ENUMERATION_ADDED, env_enumeration_added, "var home = process.env.HOME;\n"),
]


@pytest.mark.parametrize(
    ("rule_id", "fn", "severity", "line", "pattern"), DETECTIONS, ids=[d[0] for d in DETECTIONS]
)
def test_rule_metadata_matches_spec(
    rule_id: str,
    fn: Callable[[DiffContext], list[Finding]],
    severity: Severity,
    line: str,
    pattern: str,
) -> None:
    registered = {rule.rule_id: rule for rule in RULES}
    rule = registered[rule_id]
    assert rule.severity is severity
    assert rule.rule_version == 1
    assert rule.families == (RuleFamily.DANGEROUS_CAPABILITY,)
    assert rule.ecosystems == (Ecosystem.NPM,)
    assert callable(fn)


@pytest.mark.parametrize(
    ("rule_id", "fn", "severity", "line", "pattern"), DETECTIONS, ids=[d[0] for d in DETECTIONS]
)
def test_rule_fires_on_the_obvious_added_line(
    tmp_path: Path,
    rule_id: str,
    fn: Callable[[DiffContext], list[Finding]],
    severity: Severity,
    line: str,
    pattern: str,
) -> None:
    ctx = ctx_from_files(tmp_path, BASE, {**BASE, "package/index.js": line.encode()})
    findings = fn(ctx)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == rule_id
    assert finding.severity is severity
    assert finding.path == "package/index.js"
    assert finding.line_start == 1
    assert finding.line_end == 1
    assert finding.evidence == line.strip()
    assert finding.details["pattern"] == pattern
    assert finding.details["old_tree_scan"] == "full"


@pytest.mark.parametrize(
    ("rule_id", "fn", "line"), NEAR_MISSES, ids=[item[0] for item in NEAR_MISSES]
)
def test_rule_ignores_the_near_miss(
    tmp_path: Path, rule_id: str, fn: Callable[[DiffContext], list[Finding]], line: str
) -> None:
    ctx = ctx_from_files(tmp_path, BASE, {**BASE, "package/index.js": line.encode()})
    assert fn(ctx) == []


def test_capability_already_present_in_an_unchanged_old_file_is_not_new(tmp_path: Path) -> None:
    existing = b'const cp = require("child_process");\n'
    ctx = ctx_from_files(
        tmp_path,
        {"package/legacy.js": existing},
        {"package/legacy.js": existing, "package/index.js": existing},
    )
    assert js_child_process_added(ctx) == []


def test_capability_moved_between_files_is_not_new(tmp_path: Path) -> None:
    line = b'const cp = require("child_process");\n'
    ctx = ctx_from_files(tmp_path, {"package/old_home.js": line}, {"package/new_home.js": line})
    assert js_child_process_added(ctx) == []


def test_non_javascript_files_are_out_of_scope(tmp_path: Path) -> None:
    line = b'const cp = require("child_process");\n'
    ctx = ctx_from_files(tmp_path, BASE, {**BASE, "README.md": line, "docs/notes.txt": line})
    assert js_child_process_added(ctx) == []


def test_findings_are_ordered_by_path_then_line(tmp_path: Path) -> None:
    line = b'const cp = require("child_process");\n'
    ctx = ctx_from_files(
        tmp_path,
        BASE,
        {
            **BASE,
            "package/zeta.js": line,
            "package/alpha.js": b"\n".join([b"// header", line.rstrip()]),
        },
    )
    findings = js_child_process_added(ctx)
    assert [(finding.path, finding.line_start) for finding in findings] == [
        ("package/alpha.js", 2),
        ("package/zeta.js", 1),
    ]


def test_truncated_old_tree_reports_a_partial_scan(tmp_path: Path) -> None:
    limits = SandboxLimits(text_scan_bytes=64)
    padding = b"// " + b"x" * 200 + b"\n"
    hit = b'const cp = require("child_process");\n'
    ctx = ctx_from_files(
        tmp_path,
        {"package/big.js": padding + hit},
        {"package/big.js": padding + hit, "package/index.js": hit},
        limits=limits,
    )
    findings = js_child_process_added(ctx)
    assert len(findings) == 1
    assert findings[0].details["old_tree_scan"] == "partial"


def test_added_line_numbers_refer_to_the_new_file(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/index.js": b"var a = 1;\nvar b = 2;\n"},
        {"package/index.js": b"var a = 1;\nvar b = 2;\nvar c = 3;\n"},
    )
    assert "package/index.js" in ctx.files_new
    assert ctx.files_new["package/index.js"].diff_lines[-1].line_new == 3


def test_positive_fixture_emits_the_exact_child_process_finding(tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, JS_CHILD_PROCESS_ADDED, "positive")
    findings = js_child_process_added(ctx)
    assert findings == [
        Finding(
            rule_id=JS_CHILD_PROCESS_ADDED,
            rule_version=1,
            severity=Severity.HIGH,
            path="package/index.js",
            evidence='const cp = require("child_process");',
            line_start=1,
            line_end=1,
            ecosystem=ctx.ecosystem,
            package_name=ctx.package_name,
            old_version=ctx.old_version,
            new_version=ctx.new_version,
            details={"pattern": "child_process_require", "old_tree_scan": "full"},
        )
    ]


def test_negative_fixture_keeps_every_family_two_rule_quiet(tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, JS_CHILD_PROCESS_ADDED, "negative")
    for _, fn, _, _, _ in DETECTIONS:
        assert fn(ctx) == []


def test_rules_never_raise_on_binary_like_text(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, BASE, {**BASE, "package/index.js": b"\x00\x01eval(\n"})
    for _, fn, _, _, _ in DETECTIONS:
        assert fn(ctx) == []
