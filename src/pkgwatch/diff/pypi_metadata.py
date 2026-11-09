"""PyPI root metadata (PKG-INFO / METADATA) reading and parsing (SPEC §4.5.2).

The metadata document is the package's own shipped text — ``PKG-INFO`` at the root of
an sdist, ``METADATA`` inside the ``.dist-info`` directory of a wheel — never registry
data. Resolution is deterministic and parsing never raises: a malformed document simply
yields no dependencies, so a weird metadata file is not evidence of malice.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pkgwatch.models import DiffContext

_PKG_INFO = "PKG-INFO"
_METADATA = "METADATA"
_DIST_INFO_SUFFIX = ".dist-info"

_NORMALIZE_RE = re.compile(r"[-_.]+")
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$")
_EXTRAS_RE = re.compile(r"^\[[^\]]*\]\s*")

# A metadata document cannot declare an unbounded number of dependencies.
_MAX_DEPENDENCIES = 1000


@dataclass(frozen=True)
class PypiMetadata:
    """The fields the PyPI rules read: identity plus declared dependencies."""

    name: str = ""
    version: str = ""
    dependencies: dict[str, str] = field(default_factory=dict)


def _kind(path: str) -> str | None:
    """``"pkg-info"`` / ``"metadata"`` if ``path`` is a root metadata document."""
    parent, separator, leaf = path.rpartition("/")
    if not separator or "/" in parent:
        return None  # root metadata lives one directory deep, never deeper
    if leaf == _PKG_INFO:
        return "pkg-info"
    if leaf == _METADATA and parent.endswith(_DIST_INFO_SUFFIX):
        return "metadata"
    return None


def root_metadata_path(ctx: DiffContext, side: str) -> str | None:
    """The shipped metadata document on one side, or ``None`` when there is none.

    ``PKG-INFO`` wins over ``METADATA`` and ties break by path, so the pick is
    deterministic for any tree.
    """
    found: list[tuple[str, str]] = []
    for change in ctx.changes:
        path = change.path_old if side == "old" else change.path_new
        if path is None:
            continue
        kind = _kind(path)
        if kind is not None:
            found.append((kind, path))
    if not found:
        return None
    found.sort(key=lambda item: (0 if item[0] == "pkg-info" else 1, item[1]))
    return found[0][1]


def metadata_text(ctx: DiffContext, side: str) -> str | None:
    """The metadata document's text on one side, with the UNCHANGED-view fallback."""
    path = root_metadata_path(ctx, side)
    if path is None:
        return None
    primary = ctx.files_old if side == "old" else ctx.files_new
    fallback = ctx.files_new if side == "old" else ctx.files_old
    view = primary.get(path)
    if view is None:
        view = fallback.get(path)
    if view is None or not view.is_text:
        return None
    return view.content


def _normalize(name: str) -> str:
    """PEP 503: runs of ``-_.`` collapse to one ``-``, everything lowercases."""
    return _NORMALIZE_RE.sub("-", name).lower()


def _requirement(value: str) -> tuple[str, str] | None:
    """``(normalized name, specifier)`` for one Requires-Dist value, extras/markers aside."""
    core = value.split(";", 1)[0]
    match = _NAME_RE.match(core)
    if match is None:
        return None
    name = _normalize(match.group(1))
    if not name:
        return None
    specifier = _EXTRAS_RE.sub("", match.group(2).strip())
    return name, specifier


def parse_metadata(text: str) -> PypiMetadata:
    """Parse the ``Name``/``Version``/``Requires-Dist`` headers without ever raising."""
    name = ""
    version = ""
    dependencies: dict[str, str] = {}
    for line in text.splitlines():
        header, separator, value = line.partition(":")
        if not separator:
            continue
        key = header.strip().lower()
        value = value.strip()
        if key == "name" and not name:
            name = value
        elif key == "version" and not version:
            version = value
        elif key == "requires-dist" and len(dependencies) < _MAX_DEPENDENCIES:
            parsed = _requirement(value)
            if parsed is not None:
                dependencies[parsed[0]] = parsed[1]
    return PypiMetadata(name=name, version=version, dependencies=dependencies)
