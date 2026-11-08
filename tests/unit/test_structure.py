"""ARCHITECTURE §5: three structural invariants asserted by grep, not trusted by convention.

They are cheap to run and expensive to lose: the model layer cannot reach ingestion, no
package byte can ever be executed, and SQL cannot leak out of ``store/``.
"""

from __future__ import annotations

import re
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src" / "pkgwatch"

PIPELINE_PACKAGES = (
    "ingest",
    "fetch",
    "sandbox",
    "diff",
    "rules",
    "features",
    "score",
    "store",
    "dataset",
    "lockfile",
    "lock",
)

MODEL_IMPORT = re.compile(
    r"\bfrom pkgwatch\.model\b|\bimport pkgwatch\.model\b|pkgwatch\.model\.\w"
)

EXECUTION_TOKENS = (
    "subprocess",
    "eval(",
    "exec(",
    "__import__",
    "importlib.import_module",
    "os.system(",
    "pty.spawn(",
)

SQL_TOKENS = (
    "CREATE TABLE",
    "DROP TABLE",
    "INSERT INTO",
    "DELETE FROM",
    "PRAGMA ",
)
SQL_SELECT = re.compile(r"\bSELECT\b[^\"']*\bFROM\b", re.IGNORECASE)
SQL_UPDATE = re.compile(r"\bUPDATE\s+\w+\s+SET\b", re.IGNORECASE)


def _sources(*package_dirs: str) -> list[Path]:
    roots = [SOURCE_ROOT] if not package_dirs else [SOURCE_ROOT / name for name in package_dirs]
    return sorted(path for root in roots for path in root.rglob("*.py"))


def test_no_pipeline_module_imports_the_model_layer() -> None:
    for path in _sources(*PIPELINE_PACKAGES):
        assert not MODEL_IMPORT.search(path.read_text(encoding="utf-8")), path


def test_nothing_dynamic_can_execute_package_bytes() -> None:
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for token in EXECUTION_TOKENS:
            assert token not in text, (path, token)


def test_compile_is_only_ever_re_compile() -> None:
    """The one honest reading of ARCHITECTURE §5(b).

    A rule needs patterns (SPEC §4.5), and ``re.compile`` compiles a literal written by us,
    never package bytes — so the ban that matters is "no compiling of anything that came
    from a package", which is what this asserts.
    """
    for path in _sources():
        text = path.read_text(encoding="utf-8").replace("re.compile(", "")
        assert "compile(" not in text, path


def test_the_installer_is_never_referenced() -> None:
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"\bpip\b|\buv pip\b", text), path


def test_sql_text_appears_only_in_store() -> None:
    for path in _sources():
        if path.relative_to(SOURCE_ROOT).parts[0] == "store":
            continue
        text = path.read_text(encoding="utf-8")
        for token in SQL_TOKENS:
            assert token not in text, (path, token)
        assert not SQL_SELECT.search(text), path
        assert not SQL_UPDATE.search(text), path


def test_only_store_may_import_sqlite3() -> None:
    for path in _sources():
        if path.relative_to(SOURCE_ROOT).parts[0] == "store":
            continue
        assert "import sqlite3" not in path.read_text(encoding="utf-8"), path
