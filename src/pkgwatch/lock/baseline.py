"""The ``--baseline`` file: findings the operator has reviewed and accepted (SPEC §9.1).

A finding is hidden only when its (package name, rule_id, path, SHA-256 of the evidence
text) matches an entry. The version is never part of the match: the same finding at the
next release stays hidden, and changed evidence makes it reappear. Every entry stores a
mandatory reason and the date it was acknowledged. The file is JSON, sorted, and validated
on load with stable error codes — never an exception message from file content.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pkgwatch.models import Finding

BASELINE_VERSION = 1
BASELINE_NOT_FOUND = "BASELINE_NOT_FOUND"
BASELINE_INVALID = "BASELINE_INVALID"
BASELINE_REASON_REQUIRED = "BASELINE_REASON_REQUIRED"
BASELINE_WRITE_FAILED = "BASELINE_WRITE_FAILED"
BASELINE_WITH_PLAN = "BASELINE_WITH_PLAN"

# Baselines are operator files, not lockfiles, but they are still read defensively.
MAX_BASELINE_BYTES = 1 * 1024 * 1024
# The schema is shallow (root object -> entries array -> flat entry objects); anything
# deeper is hostile, so reject it before json's recursive scanner can overflow the stack.
MAX_BASELINE_DEPTH = 64

BaselineKey = tuple[str, str, str | None, str]


class BaselineError(Exception):
    """Carries a stable code only, never file content."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def evidence_sha256(evidence: str) -> str:
    """The evidence half of the match key: SHA-256 of the evidence text, hex."""
    return hashlib.sha256(evidence.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BaselineEntry:
    """One acknowledged finding: its match key plus when and why it was accepted."""

    package: str
    rule_id: str
    path: str | None
    evidence_sha256: str
    reason: str
    date: str

    def key(self) -> BaselineKey:
        return (self.package, self.rule_id, self.path, self.evidence_sha256)

    def matches(self, *, package: str, rule_id: str, path: str | None, evidence: str) -> bool:
        """The exact match rule: package, rule and path equal, evidence hashes equal."""
        return self.key() == (package, rule_id, path, evidence_sha256(evidence))


def make_entries(
    findings: Iterable[Finding], *, reason: str, today: str
) -> tuple[BaselineEntry, ...]:
    """One entry per distinct match key, stamped with the reason and today's date."""
    seen: dict[BaselineKey, BaselineEntry] = {}
    for finding in findings:
        entry = BaselineEntry(
            package=finding.package_name,
            rule_id=finding.rule_id,
            path=finding.path,
            evidence_sha256=evidence_sha256(finding.evidence),
            reason=reason,
            date=today,
        )
        seen.setdefault(entry.key(), entry)
    return tuple(
        sorted(
            seen.values(),
            key=lambda item: (item.package, item.rule_id, item.path or "", item.evidence_sha256),
        )
    )


def write_baseline(path: Path, entries: Sequence[BaselineEntry]) -> None:
    """Write the versioned JSON document; entries are stored sorted by match key."""
    ordered = sorted(
        entries,
        key=lambda item: (item.package, item.rule_id, item.path or "", item.evidence_sha256),
    )
    document = {
        "version": BASELINE_VERSION,
        "entries": [
            {
                "package": item.package,
                "rule_id": item.rule_id,
                "path": item.path,
                "evidence_sha256": item.evidence_sha256,
                "reason": item.reason,
                "date": item.date,
            }
            for item in ordered
        ],
    }
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    # Write beside the target and atomically replace it, so an interrupted write never
    # leaves a truncated baseline. The temporary file is removed on any failure; OSError
    # propagates unchanged so the caller still maps it to BASELINE_WRITE_FAILED.
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    except OSError:
        if temporary is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
        raise


def load_baseline(path: Path) -> tuple[BaselineEntry, ...]:
    """Read and validate a baseline file; any problem is a stable code."""
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_BASELINE_BYTES + 1)
    except FileNotFoundError:
        raise BaselineError(BASELINE_NOT_FOUND) from None
    except OSError:
        raise BaselineError(BASELINE_INVALID) from None
    if len(data) > MAX_BASELINE_BYTES:
        raise BaselineError(BASELINE_INVALID)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise BaselineError(BASELINE_INVALID) from None
    _check_depth(text, MAX_BASELINE_DEPTH)
    try:
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKeyError:
        raise BaselineError(BASELINE_INVALID) from None
    except (ValueError, RecursionError):
        raise BaselineError(BASELINE_INVALID) from None
    return _parse_entries(document)


class _DuplicateKeyError(Exception):
    """A JSON object repeated a key; arrived at through a malformed baseline."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result


def _check_depth(text: str, max_depth: int) -> None:
    """A string-aware nesting scan, so brackets inside JSON strings are not counted."""
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
                raise BaselineError(BASELINE_INVALID)
        elif char in "]}":
            depth -= 1


def _parse_entries(document: Any) -> tuple[BaselineEntry, ...]:
    if not isinstance(document, dict):
        raise BaselineError(BASELINE_INVALID)
    if document.get("version") != BASELINE_VERSION:
        raise BaselineError(BASELINE_INVALID)
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list):
        raise BaselineError(BASELINE_INVALID)
    return tuple(_parse_entry(item) for item in raw_entries)


def _parse_entry(raw: Any) -> BaselineEntry:
    if not isinstance(raw, dict):
        raise BaselineError(BASELINE_INVALID)
    package = raw.get("package")
    rule_id = raw.get("rule_id")
    path = raw.get("path")
    evidence_hash = raw.get("evidence_sha256")
    reason = raw.get("reason")
    date = raw.get("date")
    if (
        not isinstance(package, str)
        or not package
        or not isinstance(rule_id, str)
        or not rule_id
        or (path is not None and not isinstance(path, str))
        or not isinstance(evidence_hash, str)
        or len(evidence_hash) != 64
        or not isinstance(reason, str)
        or not reason
        or not isinstance(date, str)
        or not date
    ):
        raise BaselineError(BASELINE_INVALID)
    return BaselineEntry(
        package=package,
        rule_id=rule_id,
        path=path,
        evidence_sha256=evidence_hash,
        reason=reason,
        date=date,
    )
