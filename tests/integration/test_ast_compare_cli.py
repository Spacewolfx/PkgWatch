"""The AST block through ``compare`` on a PyPI pair (M4).

Symbol changes are report surface only: no rule consumes them, the score is unchanged, and
no source text appears in the artifact.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgwatch import cli
from pkgwatch.config import Config
from pkgwatch.models import AstLimits, SandboxLimits
from tests.support.pypi_registry import PyPIRegistry, pypi_pair_registry

OLD_VERSION = "1.0.0"
NEW_VERSION = "1.1.0"
MODULE = "demo/module.py"

OLD_MODULE = "import os\n\ndef keep() -> int:\n    return 1\n\ndef gone() -> None:\n    pass\n"
NEW_MODULE = (
    "import os\nimport sys\n\ndef keep() -> int:\n    return 2\n\ndef fresh() -> None:\n    pass\n"
)


def _registry(
    tmp_path: Path, new_module: str = NEW_MODULE, old_module: str = OLD_MODULE
) -> PyPIRegistry:
    return pypi_pair_registry(
        tmp_path,
        "demo-pkg",
        old_version=OLD_VERSION,
        new_version=NEW_VERSION,
        old_files={MODULE: old_module.encode()},
        new_files={MODULE: new_module.encode()},
    )


def _run(
    capsys: pytest.CaptureFixture[str],
    registry: PyPIRegistry,
    *extra: str,
    config: Config | None = None,
) -> tuple[int, str, str]:
    args = [
        "compare",
        f"pypi:{registry.name}@{OLD_VERSION}",
        f"pypi:{registry.name}@{NEW_VERSION}",
        "--no-cache",
        *extra,
    ]
    code = cli.main(args, client=registry, config=config or Config())
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_a_python_pair_reports_symbol_changes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _registry(tmp_path)
    code, out, err = _run(capsys, registry, "--json")
    assert code == 0, err
    payload = json.loads(out)
    assert payload["schema_version"] == 3
    changes = payload["ast_changes"]
    assert changes
    kinds = {(item["kind"], item["side"], item["symbol"]) for item in changes}
    assert ("function_changed", "new", "keep") in kinds
    assert ("function_removed", "old", "gone") in kinds
    assert ("function_added", "new", "fresh") in kinds
    assert ("import_added", "new", "sys") in kinds
    assert all(item["path"] == MODULE for item in changes)
    assert all(item["line"] >= 1 for item in changes)
    # Sorted by path, then line, then kind, then symbol: byte-stable.
    order = [(item["path"], item["line"], item["kind"], item["symbol"]) for item in changes]
    assert order == sorted(order)
    # No source text: the body of the function never reaches the report.
    assert "return 2" not in out


def test_the_symbol_block_does_not_change_the_score(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _registry(tmp_path)
    code, out, err = _run(capsys, registry, "--json")
    assert code == 0, err
    payload = json.loads(out)
    assert payload["score"] == 0
    assert payload["findings"] == []


def test_ast_changes_are_capped_with_an_explicit_counter(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    many_old = "".join(f"def a{i}():\n    pass\n" for i in range(10))
    many_new = "".join(f"def b{i}():\n    pass\n" for i in range(10))
    registry = _registry(tmp_path, many_new, many_old)
    config = Config()
    code, out, err = _run(
        capsys,
        registry,
        "--json",
        config=config.model_copy(update={"ast": config.ast.model_copy(update={"max_changes": 4})}),
    )
    assert code == 0, err
    payload = json.loads(out)
    assert len(payload["ast_changes"]) == 4
    assert payload["ast_changes_omitted"] == 16


def test_a_truncated_module_is_never_parsed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _registry(tmp_path)
    config = Config(sandbox=SandboxLimits(text_scan_bytes=16))
    code, out, err = _run(capsys, registry, "--json", config=config)
    assert code == 0, err
    payload = json.loads(out)
    assert payload["ast_changes"] == []
    assert payload["ast_changes_omitted"] == 0
    assert any("AST_INPUT_TRUNCATED" in warning for warning in payload["warnings"])


def test_the_total_budget_skips_later_modules_and_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _registry(tmp_path)
    config = Config(ast=AstLimits(max_total_bytes=16))
    code, out, err = _run(capsys, registry, "--json", config=config)

    assert code == 0, err
    payload = json.loads(out)
    assert payload["ast_changes"] == []
    assert any("AST_TOTAL_BUDGET_EXCEEDED" in warning for warning in payload["warnings"])
    assert "AST_TOTAL_BUDGET_EXCEEDED" in err


def test_a_syntax_error_keeps_the_line_level_analysis(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _registry(tmp_path, "def broken(:\n    pass\n")
    code, out, err = _run(capsys, registry, "--json")
    assert code == 0, err
    payload = json.loads(out)
    assert payload["ast_changes"] == []
    assert payload["findings"] == []
    assert any("SOURCE_SYNTAX_ERROR" in warning for warning in payload["warnings"])
    assert "SOURCE_SYNTAX_ERROR" in err
