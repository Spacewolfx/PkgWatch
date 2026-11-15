"""The Python symbol differ (M4): bounded, total and deterministic.

``ast.parse`` only builds a tree; nothing here imports or runs the module under test.
"""

from __future__ import annotations

import pytest

from pkgwatch.diff.ast import (
    BUDGET_EXCEEDED,
    NOT_PYTHON,
    SYNTAX_ERROR,
    ModuleSymbols,
    diff_modules,
    parse_module,
)
from pkgwatch.models import AstChangeKind, AstLimits, AstSide


def _symbols(source: str) -> ModuleSymbols:
    parsed = parse_module("pkg/mod.py", source, AstLimits())
    assert parsed.symbols is not None
    return parsed.symbols


def _diff(old: str, new: str, *, limits: AstLimits | None = None) -> list[tuple[str, str, str]]:
    changes, omitted = diff_modules(
        "pkg/mod.py",
        _symbols(old),
        _symbols(new),
        limits=limits or AstLimits(),
    )
    assert omitted == 0
    return [(item.kind.value, item.side.value, item.symbol) for item in changes]


def test_a_non_python_path_is_not_parsed() -> None:
    parsed = parse_module("src/main.rs", "fn main() {}", AstLimits())
    assert parsed.symbols is None
    assert parsed.detail == NOT_PYTHON


def test_an_empty_module_has_no_symbols_and_is_not_an_error() -> None:
    parsed = parse_module("pkg/empty.py", "\n  \n", AstLimits())
    assert parsed.ok
    assert parsed.symbols == ModuleSymbols()


def test_a_syntax_error_is_a_token_not_an_exception_message() -> None:
    parsed = parse_module("pkg/bad.py", "def broken(:\n    pass\n", AstLimits())
    assert parsed.symbols is None
    assert parsed.detail == SYNTAX_ERROR


def test_the_node_budget_skips_the_whole_module() -> None:
    parsed = parse_module("pkg/mod.py", "x = [1, 2, 3, 4, 5, 6]\n", AstLimits(max_nodes=3))
    assert parsed.detail == BUDGET_EXCEEDED


def test_the_depth_budget_skips_the_whole_module() -> None:
    parsed = parse_module("pkg/mod.py", "x = [[[[1]]]]\n", AstLimits(max_depth=2))
    assert parsed.detail == BUDGET_EXCEEDED


def test_nested_definitions_are_qualified_by_their_parents() -> None:
    symbols = _symbols(
        "import os.path\n"
        "from typing import Any\n"
        "class Outer:\n"
        "    def method(self):\n"
        "        def inner():\n"
        "            pass\n"
    )
    assert set(symbols.classes) == {"Outer"}
    assert set(symbols.functions) == {"Outer.method", "Outer.method.inner"}
    assert set(symbols.imports) == {"os.path", "typing.Any"}


def test_added_and_removed_functions_are_ordered_by_line() -> None:
    changes = _diff("def old():\n    pass\n", "def new():\n    pass\n")
    assert sorted(changes) == sorted(
        [
            ("function_removed", "old", "old"),
            ("function_added", "new", "new"),
        ]
    )


def test_a_body_change_is_one_function_changed() -> None:
    changes = _diff("def f():\n    return 1\n", "def f():\n    return 2\n")
    assert changes == [("function_changed", "new", "f")]


def test_a_signature_change_is_a_change_too() -> None:
    changes = _diff("def f(a):\n    return a\n", "def f(a, b=1):\n    return a\n")
    assert changes == [("function_changed", "new", "f")]


def test_reformatting_is_not_a_change() -> None:
    """Whitespace and comments do not survive the fingerprint."""
    changes = _diff("def f():\n    return 1\n", "# note\ndef f( ):\n    return  1\n")
    assert changes == []


def test_import_additions_and_removals_are_separate_rows() -> None:
    changes = _diff("import os\n", "import sys\n")
    assert sorted(changes) == sorted(
        [("import_removed", "old", "os"), ("import_added", "new", "sys")]
    )


def test_a_class_body_change_is_a_remove_plus_an_add() -> None:
    changes = _diff("class C:\n    x = 1\n", "class C:\n    x = 2\n")
    assert sorted(changes) == sorted([("class_removed", "old", "C"), ("class_added", "new", "C")])


def test_a_new_class_is_added_and_a_deleted_class_is_removed() -> None:
    changes = _diff("class Gone:\n    pass\n", "class Fresh:\n    pass\n")
    assert sorted(changes) == sorted(
        [("class_removed", "old", "Gone"), ("class_added", "new", "Fresh")]
    )


def test_the_emission_is_sorted_and_stable() -> None:
    old = "def z():\n    pass\ndef a():\n    pass\n"
    new = "def y():\n    pass\ndef b():\n    pass\n"
    first = _diff(old, new)
    second = _diff(old, new)
    assert first == second
    assert sorted(first) == sorted(
        [
            ("function_removed", "old", "a"),
            ("function_removed", "old", "z"),
            ("function_added", "new", "b"),
            ("function_added", "new", "y"),
        ]
    )


def test_a_change_to_a_shadowed_definition_is_reported() -> None:
    old = "def f():\n    return 1\n\ndef f():\n    return 2\n"
    new = "def f():\n    return 1\n\ndef f():\n    return 3\n"
    assert _diff(old, new) == [("function_changed", "new", "f")]


def test_removing_a_shadowed_definition_is_reported() -> None:
    old = "def f():\n    return 1\n\ndef f():\n    return 2\n"
    new = "def f():\n    return 1\n"
    assert _diff(old, new) == [("function_changed", "new", "f")]


def test_the_change_cap_is_reported_not_silent() -> None:
    old = "".join(f"def a{i}():\n    pass\n" for i in range(5))
    new = "".join(f"def b{i}():\n    pass\n" for i in range(5))
    changes, omitted = diff_modules(
        "pkg/mod.py", _symbols(old), _symbols(new), limits=AstLimits(max_changes=3)
    )
    assert len(changes) == 3
    assert omitted == 7
    assert all(item.side is AstSide.OLD for item in changes if "removed" in item.kind.value)
    assert all(
        item.kind in {AstChangeKind.FUNCTION_ADDED, AstChangeKind.FUNCTION_REMOVED}
        for item in changes
    )


def test_a_hostile_qualified_name_is_clipped_by_the_model() -> None:
    name = "f" * 300
    changes, _omitted = diff_modules(
        "pkg/mod.py",
        ModuleSymbols(),
        _symbols(f"def {name}():\n    pass\n"),
        limits=AstLimits(),
    )
    assert len(changes[0].symbol) == 200
    assert changes[0].symbol.endswith("\u2026")


def test_long_input_round_trips_without_raising() -> None:
    source = "".join(f"def f{i}(x):\n    return x + {i}\n" for i in range(200))
    parsed = parse_module("pkg/mod.py", source, AstLimits())
    assert parsed.ok
    assert len(parsed.symbols.functions) == 200


def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        AstLimits(max_nodes=0)
    with pytest.raises(ValueError, match="greater than 0"):
        AstLimits(max_total_bytes=0)
