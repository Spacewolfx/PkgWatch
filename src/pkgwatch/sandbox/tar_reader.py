"""tar / tar.gz validation and materialisation."""

from __future__ import annotations

import gzip
import stat
import tarfile
import zlib
from pathlib import Path

from pkgwatch.models import ArchiveFormat, ManifestKind, RejectionCode, SandboxLimits
from pkgwatch.sandbox.errors import ArchiveRejected, reject, reject_archive_error
from pkgwatch.sandbox.names import (
    normalize_hardlink_target,
    normalize_member_name,
    resolve_symlink_target,
    within_root,
)
from pkgwatch.sandbox.plan import (
    PlanBuilder,
    PlannedEntry,
    check_deadline,
    looks_like_nested_archive,
)
from pkgwatch.sandbox.write import WriteBudget, copy_exact


def _open(archive_path: Path, archive_format: ArchiveFormat) -> tarfile.TarFile:
    if archive_format is ArchiveFormat.TAR_GZ:
        return tarfile.open(archive_path, "r|gz")
    return tarfile.open(archive_path, "r|")


def plan_tar(
    archive_path: Path,
    archive_format: ArchiveFormat,
    limits: SandboxLimits,
    deadline: float,
    compressed_bytes: int,
) -> tuple[PlannedEntry, ...]:
    builder = PlanBuilder(limits, compressed_bytes, deadline)
    try:
        with _open(archive_path, archive_format) as archive:
            for info in archive:
                check_deadline(deadline)
                _add_member(builder, info, limits)
    except ArchiveRejected:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, zlib.error) as exc:
        reject_archive_error(exc)
    return builder.finish()


def materialize_tar(
    archive_path: Path,
    archive_format: ArchiveFormat,
    entries: tuple[PlannedEntry, ...],
    root: Path,
    limits: SandboxLimits,
    deadline: float,
    budget: WriteBudget,
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    planned = {entry.path: entry for entry in entries}
    try:
        with _open(archive_path, archive_format) as archive:
            for info in archive:
                check_deadline(deadline)
                path = normalize_member_name(info.name, limits)
                entry = planned.get(path)
                if entry is None:
                    reject(
                        RejectionCode.ARCHIVE_TRUNCATED,
                        "archive members changed between validation and extraction",
                    )
                destination = within_root(root, path)
                if entry.kind is ManifestKind.DIR:
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if entry.kind not in {ManifestKind.FILE, ManifestKind.NESTED_ARCHIVE}:
                    continue
                source = archive.extractfile(info)
                if source is None:
                    reject(RejectionCode.ARCHIVE_TRUNCATED, "member data is missing")
                destination.parent.mkdir(parents=True, exist_ok=True)
                with source, destination.open("xb") as output:
                    hashes[path] = copy_exact(source, output, entry.size, deadline, budget)
    except ArchiveRejected:
        raise
    except (tarfile.TarError, gzip.BadGzipFile, EOFError, zlib.error) as exc:
        reject_archive_error(exc)
    return hashes


def _add_member(builder: PlanBuilder, info: tarfile.TarInfo, limits: SandboxLimits) -> None:
    path = normalize_member_name(info.name, limits)
    mode = stat.S_IMODE(info.mode)

    if info.isdir():
        builder.add(path, ManifestKind.DIR, 0, mode)
        return
    if info.isfile():
        kind = ManifestKind.NESTED_ARCHIVE if looks_like_nested_archive(path) else ManifestKind.FILE
        builder.add(path, kind, info.size, mode)
        return
    if info.issym():
        target = resolve_symlink_target(path, info.linkname, limits)
        builder.add(path, ManifestKind.SYMLINK, 0, mode, target)
        return
    if info.islnk():
        target = normalize_hardlink_target(path, info.linkname, limits)
        builder.add(path, ManifestKind.HARDLINK, 0, mode, target)
        return
    if info.ischr() or info.isblk() or info.isfifo():
        reject(
            RejectionCode.DEVICE_OR_FIFO,
            "archive contains a device or FIFO entry",
            offending_path=path,
        )
    reject(
        RejectionCode.UNSUPPORTED_MEMBER_TYPE,
        "archive contains an unsupported member type",
        offending_path=path,
    )
