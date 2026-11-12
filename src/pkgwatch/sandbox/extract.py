"""Public extraction entry point.

Contract: validate every member, then write. Extraction happens in a temporary
directory beside the destination and is committed with a single rename, so a
rejected or failed archive never leaves a partial tree behind.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import time
from pathlib import Path

from pkgwatch.models import (
    ArchiveFormat,
    ExtractionResult,
    ManifestEntry,
    ManifestKind,
    RejectionCode,
    SandboxLimits,
)
from pkgwatch.sandbox.errors import reject
from pkgwatch.sandbox.names import within_root
from pkgwatch.sandbox.plan import PlannedEntry
from pkgwatch.sandbox.tar_reader import materialize_tar, plan_tar
from pkgwatch.sandbox.write import WriteBudget, copy_exact
from pkgwatch.sandbox.zip_reader import materialize_zip, plan_zip

_HASH_CHUNK = 1 << 20

# SPEC §TB3: observed uncompressed bytes must agree with npm dist.unpackedSize
# within 5%. The declared size is optional, so its absence skips the check.
UNPACKED_SIZE_TOLERANCE = 0.05


def cross_check_unpacked_size(observed_bytes: int, declared: object) -> None:
    """Reject when extraction disagrees with the registry's declared unpacked size.

    ``declared`` is package-controlled: anything but a positive integer (absent,
    null, a string, a bool, a float) means the registry advertised no usable size,
    so there is nothing to cross-check.
    """
    if not isinstance(declared, int) or isinstance(declared, bool) or declared <= 0:
        return
    if abs(observed_bytes - declared) > declared * UNPACKED_SIZE_TOLERANCE:
        reject(
            RejectionCode.LIMITS_DISAGREE_WITH_REGISTRY,
            "observed uncompressed bytes disagree with registry unpackedSize",
            limit_name="unpacked_size_tolerance",
            limit_value=UNPACKED_SIZE_TOLERANCE,
            observed_value=float(observed_bytes),
        )


def extract_archive(
    archive_path: Path,
    target_dir: Path,
    limits: SandboxLimits,
) -> ExtractionResult:
    """Safely unpack ``archive_path`` into ``target_dir``.

    Raises ``ArchiveRejected`` on the first violated rule and ``FileExistsError``
    if ``target_dir`` already contains files.
    """
    archive = Path(os.path.abspath(archive_path))
    if not archive.is_file():
        raise FileNotFoundError(str(archive))

    compressed_bytes = archive.stat().st_size
    if compressed_bytes > limits.max_artifact_bytes:
        reject(
            RejectionCode.ARTIFACT_TOO_LARGE,
            "archive exceeds max_artifact_bytes",
            offending_path=archive.name,
            limit_name="max_artifact_bytes",
            limit_value=float(limits.max_artifact_bytes),
            observed_value=float(compressed_bytes),
        )

    archive_format = sniff_archive(archive)
    archive_sha256 = sha256_file(archive)
    deadline = time.monotonic() + limits.extract_deadline_seconds

    if archive_format is ArchiveFormat.ZIP:
        entries = plan_zip(archive, limits, deadline, compressed_bytes)
    else:
        entries = plan_tar(archive, archive_format, limits, deadline, compressed_bytes)

    target = Path(os.path.abspath(target_dir))
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".tmp-", dir=target.parent))

    budget = WriteBudget(limit=limits.max_total_uncompressed_bytes)
    try:
        if archive_format is ArchiveFormat.ZIP:
            hashes = materialize_zip(archive, entries, temporary, limits, deadline, budget)
        else:
            hashes = materialize_tar(
                archive, archive_format, entries, temporary, limits, deadline, budget
            )
        hashes.update(materialize_hardlinks(entries, temporary, limits, deadline, budget))
        _commit(temporary, target)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)

    manifest = tuple(
        ManifestEntry(
            path=entry.path,
            kind=entry.kind,
            size=entry.size,
            mode=entry.mode,
            sha256=hashes.get(entry.path),
            link_target=entry.link_target,
        )
        for entry in entries
    )
    file_count = sum(
        1 for entry in entries if entry.kind not in {ManifestKind.DIR, ManifestKind.SYMLINK}
    )
    total_bytes = sum(
        entry.size
        for entry in entries
        if entry.kind in {ManifestKind.FILE, ManifestKind.NESTED_ARCHIVE}
    )
    return ExtractionResult(
        archive_sha256=archive_sha256,
        archive_format=archive_format,
        root=target,
        file_count=file_count,
        total_bytes=total_bytes,
        entries=manifest,
    )


def sniff_archive(archive_path: Path) -> ArchiveFormat:
    with archive_path.open("rb") as handle:
        head = handle.read(512)
    if head.startswith(b"\x1f\x8b"):
        return ArchiveFormat.TAR_GZ
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return ArchiveFormat.ZIP
    if len(head) >= 262 and head[257:262] == b"ustar":
        return ArchiveFormat.TAR
    return reject(
        RejectionCode.ARCHIVE_FORMAT_UNSUPPORTED,
        "unrecognised archive magic",
        offending_path=archive_path.name,
    )


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(_HASH_CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def materialize_hardlinks(
    entries: tuple[PlannedEntry, ...],
    root: Path,
    limits: SandboxLimits,
    deadline: float,
    budget: WriteBudget,
) -> dict[str, str]:
    """Copy in-archive hardlink targets into independent regular files."""
    hashes: dict[str, str] = {}
    for entry in entries:
        if entry.kind is not ManifestKind.HARDLINK:
            continue
        if entry.link_target is None:
            reject(
                RejectionCode.UNSUPPORTED_MEMBER_TYPE,
                "hardlink has no resolved target",
                offending_path=entry.path,
            )
        source_path = within_root(root, entry.link_target)
        destination = within_root(root, entry.path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        expected = source_path.stat().st_size
        if expected > limits.max_single_file_bytes:
            reject(
                RejectionCode.FILE_TOO_LARGE,
                "hardlink copy exceeds max_single_file_bytes",
                offending_path=entry.path,
                limit_name="max_single_file_bytes",
                limit_value=float(limits.max_single_file_bytes),
                observed_value=float(expected),
            )
        with source_path.open("rb") as source, destination.open("xb") as output:
            hashes[entry.path] = copy_exact(source, output, expected, deadline, budget)
    return hashes


def _commit(temporary: Path, target: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.exists():
        if any(target.iterdir()):
            raise FileExistsError(f"target directory is not empty: {target}")
        target.rmdir()
    os.replace(temporary, target)
