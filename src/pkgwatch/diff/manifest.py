"""Defensive parsing of the npm root manifest (SPEC §4.5.1).

Shared by the CLI's "package.json changes" section and by ``REPOSITORY_URL_CHANGED``.
Registry and package text is hostile input: nothing here raises, nothing is executed, and
every value that can reach an output is bounded to one printable line. A malformed or
non-object root manifest becomes a parse problem with the stable token
``MANIFEST_INVALID_JSON`` instead of an exception.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from pkgwatch.models import ChangeType, DiffContext, ParseError, ParseErrorKind

ROOT_MANIFEST = "package/package.json"
MANIFEST_INVALID_JSON = "MANIFEST_INVALID_JSON"
MANIFEST_SECTIONS = (
    "scripts",
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
REPOSITORY_FIELD = "repository"
VALUE_MAX_CHARS = 64
REPOSITORY_URL_SCHEMES = frozenset({"git+https", "https", "git", "git+ssh"})


def _repository_parts(value: str) -> tuple[str, str] | None:
    path = value.removesuffix("/")
    path = path.removesuffix(".git")
    parts = path.split("/")
    if len(parts) != 2 or not all(parts):
        return None
    if any(char.isspace() for char in path) or any(
        token in path for token in (":", "?", "#", "\\")
    ):
        return None
    return parts[0], parts[1]


def normalize_repository(value: str) -> tuple[str, ...]:
    """Canonicalize known repository forms; tag unknown forms so they stay raw."""
    if value.startswith("github:"):
        parts = _repository_parts(value.removeprefix("github:"))
        if parts is not None:
            return "repository", "github.com", *parts
        return "raw", value
    if "://" not in value:
        parts = _repository_parts(value)
        if parts is not None:
            return "repository", "github.com", *parts
        return "raw", value
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "raw", value
    if (
        parsed.scheme not in REPOSITORY_URL_SCHEMES
        or parsed.query
        or parsed.fragment
        or not parsed.netloc
        or not parsed.path.startswith("/")
    ):
        return "raw", value
    if parsed.scheme == "git+ssh":
        if parsed.username != "git" or parsed.password is not None:
            return "raw", value
    elif parsed.username is not None or parsed.password is not None:
        return "raw", value
    parts = _repository_parts(parsed.path[1:])
    if parts is None:
        return "raw", value
    authority = parsed.netloc.rsplit("@", 1)[-1].lower()
    return "repository", authority, *parts


@dataclass(frozen=True)
class ManifestSnapshot:
    present: bool
    sections: dict[str, dict[str, str]]
    repository: str | None
    problem: str | None = None


@dataclass(frozen=True)
class SectionChanges:
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]


@dataclass(frozen=True)
class ManifestChanges:
    sections: dict[str, SectionChanges]
    repository_old: str | None
    repository_new: str | None
    problems: tuple[tuple[str, str], ...]  # (side, stable problem code)


def _empty_sections() -> dict[str, dict[str, str]]:
    return {name: {} for name in MANIFEST_SECTIONS}


def _token(value: Any) -> str:
    """One bounded, printable line. Never echoes raw package text wholesale."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    cleaned = "".join(" " if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in text)
    return cleaned[:VALUE_MAX_CHARS]


def _section(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(key): _token(item) for key, item in raw.items()}


def _text(ctx: DiffContext, side: str) -> tuple[str | None, bool]:
    """Content of the root manifest on one side, plus whether that side has the file."""
    change = next(
        (item for item in ctx.changes if ROOT_MANIFEST in (item.path_old, item.path_new)),
        None,
    )
    if change is None:
        return None, False
    old_view = ctx.files_old.get(ROOT_MANIFEST)
    new_view = ctx.files_new.get(ROOT_MANIFEST)
    # An UNCHANGED manifest has identical bytes; diff keeps only the old-side view.
    if change.change_type is ChangeType.UNCHANGED and new_view is None:
        new_view = old_view
    if side == "old":
        present = change.path_old is not None
        view = old_view
    else:
        present = change.path_new is not None
        view = new_view
    if not present or view is None or not view.is_text:
        return None, present
    return view.content, present


def read_root_manifest(ctx: DiffContext, side: str) -> ManifestSnapshot:
    """Parse one side's root ``package.json`` without ever raising."""
    text, present = _text(ctx, side)
    if not present or text is None:
        return ManifestSnapshot(present=present, sections=_empty_sections(), repository=None)
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return ManifestSnapshot(
            present=True,
            sections=_empty_sections(),
            repository=None,
            problem=MANIFEST_INVALID_JSON,
        )
    if not isinstance(parsed, dict):
        return ManifestSnapshot(
            present=True,
            sections=_empty_sections(),
            repository=None,
            problem=MANIFEST_INVALID_JSON,
        )
    sections = {name: _section(parsed.get(name)) for name in MANIFEST_SECTIONS}
    raw_repository = parsed.get(REPOSITORY_FIELD)
    repository = None if raw_repository is None else _token(raw_repository)
    return ManifestSnapshot(present=True, sections=sections, repository=repository)


def diff_root_manifests(ctx: DiffContext) -> ManifestChanges:
    """Added/removed/changed entries per section, the repository field, and parse problems."""
    old = read_root_manifest(ctx, "old")
    new = read_root_manifest(ctx, "new")
    sections: dict[str, SectionChanges] = {}
    for name in MANIFEST_SECTIONS:
        before = old.sections[name]
        after = new.sections[name]
        sections[name] = SectionChanges(
            added=tuple(sorted(set(after) - set(before))),
            removed=tuple(sorted(set(before) - set(after))),
            changed=tuple(
                sorted(key for key in set(before) & set(after) if before[key] != after[key])
            ),
        )
    problems: list[tuple[str, str]] = []
    for side, snapshot in (("old", old), ("new", new)):
        if snapshot.problem is not None:
            problems.append((side, snapshot.problem))
    return ManifestChanges(
        sections=sections,
        repository_old=old.repository,
        repository_new=new.repository,
        problems=tuple(problems),
    )


def manifest_parse_errors(changes: ManifestChanges) -> tuple[ParseError, ...]:
    """One ``ParseError`` per malformed side; the runner turns these into engine findings."""
    return tuple(
        ParseError(path=ROOT_MANIFEST, kind=ParseErrorKind.MANIFEST, detail=MANIFEST_INVALID_JSON)
        for _ in changes.problems
    )
