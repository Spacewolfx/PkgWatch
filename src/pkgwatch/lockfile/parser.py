"""Strict parsing of untrusted package-lock.json v2/v3 files (SPEC §9.1).

No package-lock value is ever used as a filesystem path, no network call is made, and no
package content is executed. Size and JSON nesting depth are enforced before ``json``
parses the document; malformed entries are recorded with stable reason codes instead of
aborting the whole lockfile.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from pkgwatch.config import LockConfig
from pkgwatch.fetch.npm import FetchError, validate_name, validate_version

SUPPORTED_LOCKFILE_VERSIONS = frozenset({2, 3})
ROOT_PACKAGE_KEY = ""
NODE_MODULES_PREFIX = "node_modules/"
NODE_MODULES_SEGMENT = "/node_modules/"
NAME_MAX_CHARS = 214
VERSION_MAX_CHARS = 128
RESOLVED_MAX_CHARS = 2048


class LockfileErrorCode(StrEnum):
    """Stable codes; exception messages never echo lockfile-controlled text."""

    LOCKFILE_READ_FAILED = "LOCKFILE_READ_FAILED"
    LOCKFILE_NOT_FOUND = "LOCKFILE_NOT_FOUND"
    LOCKFILE_PERMISSION_DENIED = "LOCKFILE_PERMISSION_DENIED"
    LOCKFILE_NOT_UTF8 = "LOCKFILE_NOT_UTF8"
    LOCKFILE_TOO_LARGE = "LOCKFILE_TOO_LARGE"
    LOCKFILE_DEPTH_EXCEEDED = "LOCKFILE_DEPTH_EXCEEDED"
    LOCKFILE_INVALID_JSON = "LOCKFILE_INVALID_JSON"
    LOCKFILE_DUPLICATE_KEY = "LOCKFILE_DUPLICATE_KEY"
    LOCKFILE_INVALID_FORMAT = "LOCKFILE_INVALID_FORMAT"
    LOCKFILE_UNSUPPORTED_VERSION = "LOCKFILE_UNSUPPORTED_VERSION"
    TOO_MANY_PAIRS = "TOO_MANY_PAIRS"


class SkipReason(StrEnum):
    """Stable per-entry reasons; the entry is never silently dropped."""

    INVALID_ENTRY = "INVALID_ENTRY"
    INVALID_NAME = "INVALID_NAME"
    INVALID_VERSION = "INVALID_VERSION"
    INVALID_SOURCE = "INVALID_SOURCE"
    UNSUPPORTED_PATH = "UNSUPPORTED_PATH"
    LINK_SOURCE = "LINK_SOURCE"
    MISSING_RESOLVED = "MISSING_RESOLVED"
    GIT_SOURCE = "GIT_SOURCE"
    FILE_SOURCE = "FILE_SOURCE"
    HTTP_SOURCE = "HTTP_SOURCE"
    OTHER_HOST = "OTHER_HOST"
    MULTIPLE_VERSIONS = "MULTIPLE_VERSIONS"
    PAIR_SOURCE_UNSUPPORTED = "PAIR_SOURCE_UNSUPPORTED"


class LockfileError(Exception):
    """Carries a stable code only, plus the CLI argument name of the file that failed."""

    def __init__(self, code: LockfileErrorCode, *, argument: str | None = None) -> None:
        super().__init__(code.value)
        self.code = code
        self.argument = argument


@dataclass(frozen=True)
class LockEntry:
    name: str
    version: str
    resolved: str | None = None
    has_install_script: bool | None = None
    link: bool = False


@dataclass(frozen=True)
class SkippedEntry:
    name: str
    version: str | None
    reason: SkipReason


@dataclass(frozen=True)
class ParsedLockfile:
    lockfile_version: int
    entries: tuple[LockEntry, ...]
    skipped: tuple[SkippedEntry, ...]


def parse_lockfile(path: Path, *, limits: LockConfig) -> ParsedLockfile:
    """Read one lockfile and parse its v2/v3 ``packages`` map defensively."""
    try:
        with path.open("rb") as handle:
            data = handle.read(limits.max_lockfile_bytes + 1)
    except FileNotFoundError:
        raise LockfileError(LockfileErrorCode.LOCKFILE_NOT_FOUND) from None
    except PermissionError:
        raise LockfileError(LockfileErrorCode.LOCKFILE_PERMISSION_DENIED) from None
    except OSError:
        raise LockfileError(LockfileErrorCode.LOCKFILE_READ_FAILED) from None
    if len(data) > limits.max_lockfile_bytes:
        raise LockfileError(LockfileErrorCode.LOCKFILE_TOO_LARGE)
    try:
        # utf-8-sig accepts a UTF-8 BOM silently and strips it; anything else must be UTF-8.
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise LockfileError(LockfileErrorCode.LOCKFILE_NOT_UTF8) from None
    _check_depth(text, limits.max_json_depth)
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKeyError:
        raise LockfileError(LockfileErrorCode.LOCKFILE_DUPLICATE_KEY) from None
    except (ValueError, RecursionError):
        raise LockfileError(LockfileErrorCode.LOCKFILE_INVALID_JSON) from None
    return _parse_document(document)


class _DuplicateKeyError(Exception):
    """A JSON object repeated a key; ``json`` would otherwise keep the last value."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _check_depth(text: str, max_depth: int) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise LockfileError(LockfileErrorCode.LOCKFILE_DEPTH_EXCEEDED)
        elif char in "]}":
            depth -= 1


def _parse_document(document: Any) -> ParsedLockfile:
    if not isinstance(document, dict):
        raise LockfileError(LockfileErrorCode.LOCKFILE_INVALID_FORMAT)
    if "lockfileVersion" not in document:
        raise LockfileError(LockfileErrorCode.LOCKFILE_INVALID_FORMAT)
    version = document["lockfileVersion"]
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version not in SUPPORTED_LOCKFILE_VERSIONS
    ):
        raise LockfileError(LockfileErrorCode.LOCKFILE_UNSUPPORTED_VERSION)
    packages = document.get("packages")
    if not isinstance(packages, dict):
        raise LockfileError(LockfileErrorCode.LOCKFILE_INVALID_FORMAT)

    entries: dict[tuple[str, str], LockEntry] = {}
    skipped: list[SkippedEntry] = []
    for key in sorted(str(item) for item in packages):
        raw = packages[key]
        if key == ROOT_PACKAGE_KEY:
            continue
        parsed = _parse_entry(key, raw)
        if isinstance(parsed, SkippedEntry):
            skipped.append(parsed)
            continue
        entries.setdefault((parsed.name, parsed.version), parsed)

    ordered_entries = tuple(entries[identity] for identity in sorted(entries))
    ordered_skips = tuple(
        sorted(skipped, key=lambda item: (item.name, item.version or "", item.reason.value))
    )
    return ParsedLockfile(
        lockfile_version=version,
        entries=ordered_entries,
        skipped=ordered_skips,
    )


def _parse_entry(key: str, raw: Any) -> LockEntry | SkippedEntry:
    derived_name = _name_from_path(key)
    version_display = _version_display(raw) if isinstance(raw, dict) else None
    if derived_name is None:
        return SkippedEntry(
            name=_bounded_token(key, NAME_MAX_CHARS),
            version=version_display,
            reason=SkipReason.UNSUPPORTED_PATH,
        )
    if not isinstance(raw, dict):
        return SkippedEntry(
            name=_bounded_token(derived_name, NAME_MAX_CHARS),
            version=None,
            reason=SkipReason.INVALID_ENTRY,
        )

    raw_name = raw.get("name")
    if raw_name is None:
        name = derived_name
    elif isinstance(raw_name, str):
        name = raw_name
    else:
        return SkippedEntry(
            name=_bounded_token(derived_name, NAME_MAX_CHARS),
            version=version_display,
            reason=SkipReason.INVALID_NAME,
        )
    try:
        validate_name(name)
    except FetchError:
        return SkippedEntry(
            name=_bounded_token(name, NAME_MAX_CHARS),
            version=version_display,
            reason=SkipReason.INVALID_NAME,
        )

    raw_version = raw.get("version")
    if not isinstance(raw_version, str):
        return SkippedEntry(
            name=name,
            version=None,
            reason=SkipReason.INVALID_VERSION,
        )
    try:
        validate_version(raw_version)
    except FetchError:
        return SkippedEntry(
            name=name,
            version=version_display,
            reason=SkipReason.INVALID_VERSION,
        )

    link = raw.get("link", False)
    if not isinstance(link, bool):
        return SkippedEntry(name=name, version=raw_version, reason=SkipReason.INVALID_ENTRY)
    has_install_script = raw.get("hasInstallScript")
    if has_install_script is not None and not isinstance(has_install_script, bool):
        return SkippedEntry(name=name, version=raw_version, reason=SkipReason.INVALID_ENTRY)
    resolved = raw.get("resolved")
    if resolved is not None and (
        not isinstance(resolved, str) or len(resolved) > RESOLVED_MAX_CHARS
    ):
        return SkippedEntry(name=name, version=raw_version, reason=SkipReason.INVALID_SOURCE)
    return LockEntry(
        name=name,
        version=raw_version,
        resolved=resolved,
        has_install_script=has_install_script,
        link=link,
    )


def _name_from_path(key: str) -> str | None:
    if not key.startswith(NODE_MODULES_PREFIX):
        return None
    tail = key[len(NODE_MODULES_PREFIX) :]
    if not tail:
        return None
    return tail.rsplit(NODE_MODULES_SEGMENT, 1)[-1]


def _version_display(raw: dict[str, Any]) -> str | None:
    value = raw.get("version")
    return _bounded_token(value, VERSION_MAX_CHARS) if isinstance(value, str) else None


def _bounded_token(value: str, max_chars: int) -> str:
    cleaned = "".join(" " if ord(char) < 0x20 or ord(char) == 0x7F else char for char in value)
    return cleaned[:max_chars]
