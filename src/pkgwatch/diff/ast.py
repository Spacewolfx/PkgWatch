"""Symbol-level comparison of Python modules (SPEC §4.6, M4-B).

Only the standard library parser is used: ``ast.parse`` builds a tree from text and never
imports, compiles to bytecode or runs the module. JavaScript/TypeScript/Rust would need a
third-party parser, which is a dependency decision this codebase does not take silently, so
those files keep the line-level differ (``diff/files.py``).

Three properties matter more than detail here:

- **total**: ``parse_module`` never raises. A ``SyntaxError`` message quotes hostile source,
  so the failure is reported as a stable token, never as an exception string.
- **bounded**: a node/depth budget skips a whole module and records it; a half-parsed tree
  would describe code that is not there.
- **deterministic**: symbol tables are dicts keyed by qualified name and every emission is
  sorted, so the same input produces byte-identical output.

A symbol change is a *name* plus a *line*, never a source excerpt. Matching is by qualified
name, so a rename is one removed plus one added, the same choice ``diff/files.py`` makes for
files. ``function_changed`` compares a fingerprint of the node (signature plus body), which
is a change indicator with no threshold to tune; there is no ``class_changed`` because a
class body can contain arbitrary statements and one row would say less than two.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Final

from pkgwatch.models import AstChange, AstChangeKind, AstLimits, AstSide

PYTHON_SUFFIX: Final = ".py"
SYNTAX_ERROR: Final = "SOURCE_SYNTAX_ERROR"
BUDGET_EXCEEDED: Final = "AST_BUDGET_EXCEEDED"
NOT_PYTHON: Final = "NOT_PYTHON"
INPUT_TRUNCATED: Final = "AST_INPUT_TRUNCATED"


@dataclass(frozen=True)
class SymbolInfo:
    """One definition: where it starts and what its text hashed to."""

    line: int
    fingerprint: str


@dataclass(frozen=True)
class ModuleSymbols:
    """Qualified names on one side of a diff; empty tables are valid (a new/removed file)."""

    functions: dict[str, SymbolInfo] = field(default_factory=dict)
    classes: dict[str, SymbolInfo] = field(default_factory=dict)
    imports: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class ModuleParse:
    """Either symbols, or a stable detail token explaining why there are none."""

    symbols: ModuleSymbols | None
    detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.symbols is not None


def parse_module(path: str, content: str, limits: AstLimits) -> ModuleParse:
    """Parse one module into its symbol table, or return a token; never raise.

    ``content`` is already the ``FileView`` text (bounded by ``text_scan_bytes``); a
    truncated view must not be passed here, because a cut module can parse into a plausible
    but wrong tree.
    """
    if not path.lower().endswith(PYTHON_SUFFIX):
        return ModuleParse(None, NOT_PYTHON)
    if not content.strip():
        return ModuleParse(ModuleSymbols())
    try:
        tree = ast.parse(content, filename="")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return ModuleParse(None, SYNTAX_ERROR)
    try:
        if not _within_budget(tree, limits):
            return ModuleParse(None, BUDGET_EXCEEDED)
        return ModuleParse(_symbols(tree))
    except (RecursionError, MemoryError):
        return ModuleParse(None, BUDGET_EXCEEDED)


def diff_modules(
    path: str,
    old: ModuleSymbols,
    new: ModuleSymbols,
    *,
    limits: AstLimits,
) -> tuple[list[AstChange], int]:
    """Compare two symbol tables into sorted changes plus the count that did not fit."""
    changes: list[AstChange] = []

    for name in sorted(old.classes.keys() - new.classes.keys()):
        changes.append(_change(path, AstSide.OLD, AstChangeKind.CLASS_REMOVED, name, old, "c"))
    for name in sorted(new.classes.keys() - old.classes.keys()):
        changes.append(_change(path, AstSide.NEW, AstChangeKind.CLASS_ADDED, name, new, "c"))
    for name in sorted(old.classes.keys() & new.classes.keys()):
        if old.classes[name].fingerprint != new.classes[name].fingerprint:
            changes.append(_change(path, AstSide.OLD, AstChangeKind.CLASS_REMOVED, name, old, "c"))
            changes.append(_change(path, AstSide.NEW, AstChangeKind.CLASS_ADDED, name, new, "c"))

    for name in sorted(old.functions.keys() - new.functions.keys()):
        changes.append(_change(path, AstSide.OLD, AstChangeKind.FUNCTION_REMOVED, name, old, "f"))
    for name in sorted(new.functions.keys() - old.functions.keys()):
        changes.append(_change(path, AstSide.NEW, AstChangeKind.FUNCTION_ADDED, name, new, "f"))
    for name in sorted(old.functions.keys() & new.functions.keys()):
        if old.functions[name].fingerprint != new.functions[name].fingerprint:
            changes.append(
                _change(path, AstSide.NEW, AstChangeKind.FUNCTION_CHANGED, name, new, "f")
            )

    for name in sorted(old.imports.keys() - new.imports.keys()):
        changes.append(_change(path, AstSide.OLD, AstChangeKind.IMPORT_REMOVED, name, old, "i"))
    for name in sorted(new.imports.keys() - old.imports.keys()):
        changes.append(_change(path, AstSide.NEW, AstChangeKind.IMPORT_ADDED, name, new, "i"))

    changes.sort(key=lambda item: (item.path, item.line, item.kind.value, item.symbol))
    kept = changes[: limits.max_changes]
    return kept, len(changes) - len(kept)


def _change(
    path: str,
    side: AstSide,
    kind: AstChangeKind,
    name: str,
    symbols: ModuleSymbols,
    table: str,
) -> AstChange:
    line = (
        symbols.imports[name]
        if table == "i"
        else (symbols.functions if table == "f" else symbols.classes)[name].line
    )
    return AstChange(path=path, side=side, kind=kind, symbol=name, line=max(1, line))


def _within_budget(tree: ast.AST, limits: AstLimits) -> bool:
    """Node count and depth in one pass, iteratively (deep input cannot blow the stack)."""
    count = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > limits.max_nodes or depth > limits.max_depth:
            return False
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return True


def _symbols(tree: ast.AST) -> ModuleSymbols:
    out = ModuleSymbols()
    _collect(tree, "", out)
    return out


def _collect(node: ast.AST, prefix: str, out: ModuleSymbols) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
            name = f"{prefix}.{child.name}" if prefix else child.name
            out.functions.setdefault(name, SymbolInfo(child.lineno, _fingerprint(child)))
            _collect(child, name, out)
        elif isinstance(child, ast.ClassDef):
            name = f"{prefix}.{child.name}" if prefix else child.name
            out.classes.setdefault(name, SymbolInfo(child.lineno, _fingerprint(child)))
            _collect(child, name, out)
        elif isinstance(child, ast.Import):
            for alias in child.names:
                out.imports.setdefault(alias.name, child.lineno)
        elif isinstance(child, ast.ImportFrom):
            module = child.module or ""
            for alias in child.names:
                dotted = f"{module}.{alias.name}" if module else alias.name
                out.imports.setdefault(dotted, child.lineno)
        else:
            _collect(child, prefix, out)


def _fingerprint(node: ast.AST) -> str:
    """SHA-256 of a canonical rendering: whitespace and comments do not survive it."""
    rendered = ast.dump(node, annotate_fields=False, include_attributes=False)
    return hashlib.sha256(rendered.encode("utf-8", "replace")).hexdigest()
