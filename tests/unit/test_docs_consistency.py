"""The catalog and the release headers state versions; the code is the truth.

SPEC §4.1 bumps ``rule_version`` on any change to detection semantics, so a catalog row
that keeps the old number tells a reader the wrong thing about a recorded finding. The
same applies to the distribution version and the report schema versions quoted in prose.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkgwatch import __version__
from pkgwatch.cli import COMPARE_JSON_SCHEMA_VERSION
from pkgwatch.lock.report import LOCK_JSON_SCHEMA_VERSION
from pkgwatch.models import SCHEMA_VERSION
from pkgwatch.rules import RULES
from pkgwatch.rules.registry import Rule

REPO_ROOT = Path(__file__).resolve().parents[2]


def _catalog_rows() -> dict[str, tuple[str, list[str]]]:
    """rule_id -> (ecosystem heading, table cells) as written in docs/rules.md."""
    rows: dict[str, tuple[str, list[str]]] = {}
    section = ""
    for line in (REPO_ROOT / "docs" / "rules.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            section = line[3:].strip().lower()
        if line.startswith("| `"):
            cells = [cell.strip() for cell in line.split("|")[1:-1]]
            rows[cells[0].strip("`")] = (section, cells)
    return rows


def test_the_catalog_lists_exactly_the_registered_rules() -> None:
    assert set(_catalog_rows()) == {rule.rule_id for rule in RULES}


@pytest.mark.parametrize("rule", RULES, ids=lambda rule: rule.rule_id)
def test_the_catalog_row_matches_the_registry(rule: Rule) -> None:
    section, cells = _catalog_rows()[rule.rule_id]

    assert len(rule.ecosystems) == 1
    assert section == rule.ecosystems[0].value
    assert cells[2] == rule.severity.value
    assert len(cells) >= 4, "the catalog row needs a rule_version column"
    assert cells[3] == str(rule.rule_version)


def test_the_readme_names_the_shipped_version() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert f"version {__version__}" in readme


def test_the_spec_header_names_the_shipped_version_and_schema_versions() -> None:
    spec = (REPO_ROOT / "SPEC.md").read_text(encoding="utf-8")
    header = "\n".join(spec.splitlines()[:5])

    assert f"Version {__version__}" in header
    assert f"compare schema_version {COMPARE_JSON_SCHEMA_VERSION}" in header
    assert f"lock schema_version {LOCK_JSON_SCHEMA_VERSION}" in header
    assert f"store schema_version {SCHEMA_VERSION}" in header
