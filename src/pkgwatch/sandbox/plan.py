"""Build and validate an extraction plan before a single byte is written."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace

from pkgwatch.models import ManifestKind, RejectionCode, SandboxLimits
from pkgwatch.sandbox.errors import reject

# Tar/gzip framing is a few hundred bytes for a tiny archive, so a strict ratio cap
# rejects legitimate small packages. Only enforce the ratio once real volume exists.
RATIO_CHECK_MIN_BYTES = 1 << 20

_NESTED_SUFFIXES = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tgz",
    ".tbz2",
    ".txz",
    ".tar",
    ".zip",
    ".whl",
    ".crate",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
)


@dataclass(frozen=True, slots=True)
class PlannedEntry:
    path: str
    kind: ManifestKind
    size: int
    mode: int
    link_target: str | None = None


def check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        reject(RejectionCode.DEADLINE_EXCEEDED, "extraction deadline exceeded")


def looks_like_nested_archive(path: str) -> bool:
    return path.lower().endswith(_NESTED_SUFFIXES)


class PlanBuilder:
    """Accumulates members and rejects the archive on the first violated rule."""

    def __init__(
        self,
        limits: SandboxLimits,
        compressed_bytes: int,
        deadline: float,
    ) -> None:
        self._limits = limits
        self._compressed_bytes = max(1, compressed_bytes)
        self._deadline = deadline
        self._entries: dict[str, PlannedEntry] = {}
        self._casefold: dict[str, str] = {}
        self._file_count = 0
        self._total_bytes = 0

    def add(
        self,
        path: str,
        kind: ManifestKind,
        size: int,
        mode: int,
        link_target: str | None = None,
    ) -> None:
        """Add an already-normalised path. Name validation happens in the reader."""
        if size < 0:
            reject(
                RejectionCode.UNSUPPORTED_MEMBER_TYPE,
                "member declares a negative size",
                offending_path=path,
            )
        if size > self._limits.max_single_file_bytes:
            reject(
                RejectionCode.FILE_TOO_LARGE,
                "member exceeds max_single_file_bytes",
                offending_path=path,
                limit_name="max_single_file_bytes",
                limit_value=float(self._limits.max_single_file_bytes),
                observed_value=float(size),
            )
        if kind is not ManifestKind.DIR:
            self._file_count += 1
            if self._file_count > self._limits.max_file_count:
                reject(
                    RejectionCode.FILE_COUNT_EXCEEDED,
                    "archive exceeds max_file_count",
                    limit_name="max_file_count",
                    limit_value=float(self._limits.max_file_count),
                    observed_value=float(self._file_count),
                )
        self._total_bytes += size
        if self._total_bytes > self._limits.max_total_uncompressed_bytes:
            reject(
                RejectionCode.TOTAL_UNCOMPRESSED_EXCEEDED,
                "archive exceeds max_total_uncompressed_bytes",
                limit_name="max_total_uncompressed_bytes",
                limit_value=float(self._limits.max_total_uncompressed_bytes),
                observed_value=float(self._total_bytes),
            )
        self._check_ratio()

        folded = path.casefold()
        existing_path = self._casefold.get(folded)
        if existing_path is not None:
            existing = self._entries[existing_path]
            if existing_path != path:
                reject(
                    RejectionCode.CASE_COLLISION,
                    "two members differ only by case",
                    offending_path=path,
                )
            if existing.kind is ManifestKind.DIR and kind is ManifestKind.DIR:
                return
            reject(
                RejectionCode.DUPLICATE_MEMBER,
                "duplicate member path",
                offending_path=path,
            )

        self._entries[path] = PlannedEntry(
            path=path,
            kind=kind,
            size=size,
            mode=mode,
            link_target=link_target,
        )
        self._casefold[folded] = path

    def finish(self) -> tuple[PlannedEntry, ...]:
        check_deadline(self._deadline)
        self._check_ratio()
        self._validate_parents()
        resolved_links = self._resolve_hardlinks()
        entries = [
            replace(entry, link_target=resolved_links[entry.path])
            if entry.kind is ManifestKind.HARDLINK
            else entry
            for entry in self._entries.values()
        ]
        return tuple(sorted(entries, key=lambda entry: entry.path))

    def _check_ratio(self) -> None:
        if self._total_bytes < RATIO_CHECK_MIN_BYTES:
            return
        ratio = self._total_bytes / self._compressed_bytes
        if ratio > self._limits.max_compression_ratio:
            reject(
                RejectionCode.COMPRESSION_RATIO_EXCEEDED,
                "archive exceeds max_compression_ratio",
                limit_name="max_compression_ratio",
                limit_value=self._limits.max_compression_ratio,
                observed_value=ratio,
            )

    def _validate_parents(self) -> None:
        for path in self._entries:
            parts = path.split("/")
            for index in range(1, len(parts)):
                ancestor = "/".join(parts[:index])
                entry = self._entries.get(ancestor)
                if entry is None:
                    continue
                if entry.kind is ManifestKind.SYMLINK:
                    reject(
                        RejectionCode.PARENT_IS_SYMLINK,
                        "member path traverses a symlink",
                        offending_path=path,
                    )
                if entry.kind is not ManifestKind.DIR:
                    reject(
                        RejectionCode.PATH_CONFLICT,
                        "member path traverses a non-directory entry",
                        offending_path=path,
                    )

    def _resolve_hardlinks(self) -> dict[str, str]:
        resolved: dict[str, str] = {}
        for entry in self._entries.values():
            if entry.kind is not ManifestKind.HARDLINK:
                continue
            seen = {entry.path}
            current = entry
            while True:
                target_path = current.link_target
                if target_path is None:
                    reject(
                        RejectionCode.UNSUPPORTED_MEMBER_TYPE,
                        "hardlink has no target",
                        offending_path=entry.path,
                    )
                if target_path in seen:
                    reject(
                        RejectionCode.HARDLINK_CYCLE,
                        "hardlink chain contains a cycle",
                        offending_path=entry.path,
                    )
                seen.add(target_path)
                target = self._entries.get(target_path)
                if target is None:
                    reject(
                        RejectionCode.HARDLINK_MISSING_TARGET,
                        "hardlink target is not present in the archive",
                        offending_path=entry.path,
                    )
                if target.kind is ManifestKind.HARDLINK:
                    current = target
                    continue
                if target.kind in {ManifestKind.FILE, ManifestKind.NESTED_ARCHIVE}:
                    resolved[entry.path] = target_path
                    break
                reject(
                    RejectionCode.HARDLINK_MISSING_TARGET,
                    "hardlink target is not a materialised regular file",
                    offending_path=entry.path,
                )
        return resolved
