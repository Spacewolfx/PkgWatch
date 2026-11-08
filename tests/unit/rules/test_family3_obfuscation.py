"""Family 3 obfuscation signals: ADDED lines only, thresholds from config, no intent claims."""

from __future__ import annotations

from pathlib import Path

from pkgwatch.models import ObfuscationLimits, RuleFamily, Severity
from pkgwatch.rules import RULES
from pkgwatch.rules.family3_obfuscation import (
    LIKELY_MINIFIED_LINE_LENGTH,
    base64_blob_present,
    hex_escape_density,
    high_entropy_strings,
)
from tests.support.context import ctx_from_files

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
BLOB = (ALPHA * 10)[:520]
LITERAL = (ALPHA * 2)[:96]
OLD = {"package/base.js": b"var base = 1;\n"}


def test_base64_blob_is_reported_without_echoing_the_blob(
    tmp_path: Path,
) -> None:
    ctx = ctx_from_files(
        tmp_path,
        OLD,
        {"package/dist/bundle.min.js": f'var d = "{BLOB}";\n'.encode()},
    )
    findings = base64_blob_present(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "BASE64_BLOB_PRESENT"
    assert finding.severity is Severity.LOW
    assert finding.rule_version == 1
    assert finding.path == "package/dist/bundle.min.js"  # *.min.js / dist/ is no exemption
    assert finding.details["likely_minified"] is True
    assert finding.details["length"] == len(BLOB)
    assert BLOB not in finding.evidence
    assert len(finding.evidence) <= 200


def test_a_short_blob_is_ignored(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, OLD, {"package/blob.js": b'var d = "QUJDREVGR0g=";\n'})
    assert base64_blob_present(ctx) == []


def test_an_unchanged_blob_has_no_added_lines(tmp_path: Path) -> None:
    file = {"package/blob.js": f'var d = "{BLOB}";\n'.encode()}
    ctx = ctx_from_files(tmp_path, file, file)
    assert base64_blob_present(ctx) == []


def test_high_entropy_literal_is_reported_without_the_literal(
    tmp_path: Path,
) -> None:
    ctx = ctx_from_files(tmp_path, OLD, {"package/entropy.js": f'var t = "{LITERAL}";\n'.encode()})
    findings = high_entropy_strings(ctx)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "HIGH_ENTROPY_STRINGS"
    assert finding.severity is Severity.LOW
    assert float(finding.details["entropy_bits"]) >= 4.5
    assert finding.details["likely_minified"] is False
    assert LITERAL not in finding.evidence
    assert len(finding.evidence) <= 200


def test_a_long_but_low_entropy_literal_is_ignored(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, OLD, {"package/entropy.js": b'var t = "' + b"a" * 80 + b'";\n'})
    assert high_entropy_strings(ctx) == []


def test_escape_density_is_reported(tmp_path: Path) -> None:
    ctx = ctx_from_files(
        tmp_path, OLD, {"package/escapes.js": b'var t = "' + b"\\x41" * 22 + b'";\n'}
    )
    findings = hex_escape_density(ctx)

    assert len(findings) == 1
    assert findings[0].rule_id == "HEX_ESCAPE_DENSITY"
    assert findings[0].severity is Severity.LOW
    assert findings[0].details["escapes"] == 22
    assert findings[0].details["likely_minified"] is False
    assert "41" not in findings[0].evidence


def test_few_escapes_are_ignored(tmp_path: Path) -> None:
    ctx = ctx_from_files(tmp_path, OLD, {"package/escapes.js": b'var t = "\\x41\\x42";\n'})
    assert hex_escape_density(ctx) == []


def test_thresholds_come_from_config(tmp_path: Path) -> None:
    blob_file = {"package/bundle.js": f'var d = "{BLOB}";\n'.encode()}
    escape_file = {"package/escapes.js": b'var t = "' + b"\\x41" * 22 + b'";\n'}
    strict = ObfuscationLimits(
        min_blob_length=1000, entropy_threshold_bits=9.0, min_escapes_per_line=50
    )

    assert base64_blob_present(ctx_from_files(tmp_path, OLD, blob_file, obfuscation=strict)) == []
    assert high_entropy_strings(ctx_from_files(tmp_path, OLD, blob_file, obfuscation=strict)) == []
    assert hex_escape_density(ctx_from_files(tmp_path, OLD, escape_file, obfuscation=strict)) == []


def test_family_three_rules_are_low_version_one_and_report_only_signals() -> None:
    family = [rule for rule in RULES if RuleFamily.OBFUSCATION in rule.families]
    assert [rule.rule_id for rule in family] == [
        "BASE64_BLOB_PRESENT",
        "HIGH_ENTROPY_STRINGS",
        "HEX_ESCAPE_DENSITY",
    ]
    assert all(rule.severity is Severity.LOW for rule in family)
    assert all(rule.rule_version == 1 for rule in family)
    assert LIKELY_MINIFIED_LINE_LENGTH == 500
