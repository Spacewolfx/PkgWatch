"""Family 1 (npm lifecycle scripts).

Exact findings are asserted: rule identity, severity, file, line range and evidence.
"""

from __future__ import annotations

from pathlib import Path

from pkgwatch.models import Finding, RuleFamily, Severity
from pkgwatch.rules import RULES
from pkgwatch.rules.family1_lifecycle import (
    NPM_INSTALL_SCRIPT_ADDED,
    NPM_SCRIPT_INJECTION_FROM_METADATA,
    npm_install_script_added,
    npm_script_injection_from_metadata,
)
from pkgwatch.rules.runner import RULE_ENGINE_RULE_ID, run_rules
from tests.support.context import ctx_from_files
from tests.support.fixtures import rule_context

SCRIPTS = ("{", '  "name": "demo-pkg",', '  "version": "1.0.0",', '  "scripts": {')
OLD_MANIFEST = "\n".join([*SCRIPTS, '    "test": "echo run tests"', "  }", "}", ""])


def manifest(version: str, scripts: list[str]) -> bytes:
    body = ["{", '  "name": "demo-pkg",', f'  "version": "{version}",', '  "scripts": {']
    for line in scripts:
        body.append(f"    {line}")
    body += ["  }", "}", ""]
    return "\n".join(body).encode("utf-8")


EMPTY_SCRIPTS = b'{\n  "name": "demo-pkg",\n  "scripts": {}\n}\n'


def test_rules_are_registered_in_family_one() -> None:
    registered = {rule.rule_id: rule for rule in RULES}
    install = registered[NPM_INSTALL_SCRIPT_ADDED]
    assert install.severity is Severity.HIGH
    assert install.rule_version == 2
    assert install.families == (RuleFamily.LIFECYCLE_SCRIPTS,)

    metadata = registered[NPM_SCRIPT_INJECTION_FROM_METADATA]
    assert metadata.families == (RuleFamily.LIFECYCLE_SCRIPTS,)


def test_positive_fixture_emits_the_exact_install_script_finding(tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, NPM_INSTALL_SCRIPT_ADDED, "positive")
    findings = npm_install_script_added(ctx)

    assert findings == [
        Finding(
            rule_id=NPM_INSTALL_SCRIPT_ADDED,
            rule_version=2,
            severity=Severity.HIGH,
            path="package/package.json",
            evidence='"postinstall": "echo installed",',
            line_start=5,
            line_end=5,
            ecosystem=ctx.ecosystem,
            package_name=ctx.package_name,
            old_version=ctx.old_version,
            new_version=ctx.new_version,
            details={"script": "postinstall"},
        )
    ]


def test_negative_fixture_keeps_family_one_install_script_quiet(tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, NPM_INSTALL_SCRIPT_ADDED, "negative")
    assert npm_install_script_added(ctx) == []


def test_all_three_install_time_keys_are_detected(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": EMPTY_SCRIPTS},
        {
            "package/package.json": manifest(
                "1.1.0",
                [
                    '"preinstall": "echo one",',
                    '"postinstall": "echo two",',
                    '"install": "echo three"',
                ],
            )
        },
    )
    findings = npm_install_script_added(ctx)
    assert [finding.details["script"] for finding in findings] == [
        "preinstall",
        "postinstall",
        "install",
    ]
    assert [finding.line_start for finding in findings] == [5, 6, 7]
    assert all(finding.severity is Severity.HIGH for finding in findings)


def test_scripts_that_do_not_run_at_install_time_are_ignored(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": EMPTY_SCRIPTS},
        {
            "package/package.json": manifest(
                "1.1.0",
                [
                    '"prepare": "echo pack only",',
                    '"prepublishOnly": "echo publish only",',
                    '"test": "echo tests"',
                ],
            )
        },
    )
    assert npm_install_script_added(ctx) == []


def test_a_dependency_named_like_an_install_script_is_not_a_hook(tmp_path: Path) -> None:
    # "install" and "preinstall" are real npm package names; declaring them as
    # dependencies is not a lifecycle hook, so only the scripts section may fire.
    new = (
        b"{\n"
        b'  "name": "demo-pkg",\n'
        b'  "version": "1.1.0",\n'
        b'  "scripts": {\n'
        b'    "test": "echo run tests"\n'
        b"  },\n"
        b'  "dependencies": {\n'
        b'    "install": "^1.0.0",\n'
        b'    "preinstall": "^2.0.0"\n'
        b"  }\n"
        b"}\n"
    )
    ctx = ctx_from_files(
        tmp_path, {"package/package.json": EMPTY_SCRIPTS}, {"package/package.json": new}
    )
    assert npm_install_script_added(ctx) == []


def test_multiple_hooks_on_one_minified_line_are_all_reported(tmp_path: Path) -> None:
    new = b'{"name":"demo-pkg","scripts":{"preinstall":"echo one","postinstall":"echo two"}}\n'
    ctx = ctx_from_files(
        tmp_path, {"package/package.json": EMPTY_SCRIPTS}, {"package/package.json": new}
    )
    findings = npm_install_script_added(ctx)
    assert [finding.details["script"] for finding in findings] == ["preinstall", "postinstall"]
    assert all(finding.line_start == 1 and finding.line_end == 1 for finding in findings)


def test_nested_and_vendored_manifests_are_not_this_package_hook(tmp_path: Path) -> None:
    added = b'{\n  "scripts": {\n    "postinstall": "echo other"\n  }\n}\n'
    ctx = ctx_from_files(
        tmp_path,
        {
            "package/package.json": EMPTY_SCRIPTS,
            "package/fixtures/package.json": EMPTY_SCRIPTS,
        },
        {
            "package/package.json": EMPTY_SCRIPTS,
            "package/fixtures/package.json": added,
            "node_modules/dep/package.json": added,
        },
    )
    assert npm_install_script_added(ctx) == []


def test_missing_manifest_in_the_new_tree_is_not_reported(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": manifest("1.0.0", ['"postinstall": "echo old"'])},
        {"package/index.js": b"module.exports = {};\n"},
    )
    assert npm_install_script_added(ctx) == []


def test_metadata_rule_reports_a_declared_install_script(tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, NPM_SCRIPT_INJECTION_FROM_METADATA, "positive")
    findings = npm_script_injection_from_metadata(ctx)

    assert findings == [
        Finding(
            rule_id=NPM_SCRIPT_INJECTION_FROM_METADATA,
            rule_version=1,
            severity=Severity.HIGH,
            path=None,
            evidence="preinstall: echo step one",
            line_start=None,
            line_end=None,
            ecosystem=ctx.ecosystem,
            package_name=ctx.package_name,
            old_version=ctx.old_version,
            new_version=ctx.new_version,
            details={"script": "preinstall", "source": "registry_metadata"},
        )
    ]


def test_metadata_rule_ignores_unchanged_or_non_lifecycle_scripts(tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, NPM_SCRIPT_INJECTION_FROM_METADATA, "negative")
    assert npm_script_injection_from_metadata(ctx) == []


def test_metadata_rule_is_quiet_without_registry_metadata(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": EMPTY_SCRIPTS},
        {"package/package.json": manifest("1.1.0", ['"postinstall": "echo installed"'])},
    )
    assert npm_script_injection_from_metadata(ctx) == []


def test_metadata_rule_survives_a_hostile_metadata_shape(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path,
        {"package/package.json": EMPTY_SCRIPTS},
        {"package/package.json": EMPTY_SCRIPTS},
        metadata_before={"scripts": None},
        metadata_after={"scripts": {"postinstall": ["not", "a", "string"]}},
    )
    findings = run_rules(ctx)
    assert all(finding.rule_id != NPM_SCRIPT_INJECTION_FROM_METADATA for finding in findings)
    assert [f for f in findings if f.rule_id == RULE_ENGINE_RULE_ID] == []


def test_runner_collects_family_one_from_the_real_fixture(tmp_path: Path) -> None:
    ctx = rule_context(tmp_path, NPM_INSTALL_SCRIPT_ADDED, "positive")
    ids = [finding.rule_id for finding in run_rules(ctx)]
    assert NPM_INSTALL_SCRIPT_ADDED in ids
    assert RULE_ENGINE_RULE_ID not in ids
