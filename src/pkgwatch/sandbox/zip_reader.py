"""zip validation and materialisation (sdists and wheels can be zip containers)."""

from __future__ import annotations

import stat
import zipfile
import zlib
from pathlib import Path
from typing import NoReturn

from pkgwatch.models import ManifestKind, RejectionCode, SandboxLimits
from pkgwatch.sandbox.errors import ArchiveRejected, reject, reject_archive_error
from pkgwatch.sandbox.names import (
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


def plan_zip(
    archive_path: Path,
    limits: SandboxLimits,
    deadline: float,
    compressed_bytes: int,
) -> tuple[PlannedEntry, ...]:
    builder = PlanBuilder(limits, compressed_bytes, deadline)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                check_deadline(deadline)
                _add_member(builder, archive, info, limits)
    except ArchiveRejected:
        raise
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error) as exc:
        _reject_zip_error(exc)
    return builder.finish()


def materialize_zip(
    archive_path: Path,
    entries: tuple[PlannedEntry, ...],
    root: Path,
    limits: SandboxLimits,
    deadline: float,
    budget: WriteBudget,
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    planned = {entry.path: entry for entry in entries}
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                check_deadline(deadline)
                path = normalize_member_name(info.filename, limits)
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
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, destination.open("xb") as output:
                    hashes[path] = copy_exact(source, output, entry.size, deadline, budget)
    except ArchiveRejected:
        raise
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, zlib.error) as exc:
        _reject_zip_error(exc)
    return hashes


def _add_member(
    builder: PlanBuilder,
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limits: SandboxLimits,
) -> None:
    path = normalize_member_name(info.filename, limits)
    if info.flag_bits & 0x1:
        reject(
            RejectionCode.ENCRYPTED_ENTRY,
            "zip entry is encrypted",
            offending_path=path,
        )

    unix_mode = info.external_attr >> 16
    if stat.S_ISLNK(unix_mode):
        with archive.open(info) as handle:
            raw_target = handle.read(limits.max_entry_path_len + 1)
        if len(raw_target) > limits.max_entry_path_len:
            reject(
                RejectionCode.SYMLINK_TARGET_TOO_LONG,
                "symlink target exceeds max_entry_path_len",
                offending_path=path,
                limit_name="max_entry_path_len",
                limit_value=float(limits.max_entry_path_len),
                observed_value=float(len(raw_target)),
            )
        target = resolve_symlink_target(path, raw_target.decode("utf-8", "replace"), limits)
        builder.add(path, ManifestKind.SYMLINK, 0, stat.S_IMODE(unix_mode), target)
        return

    if (
        stat.S_ISCHR(unix_mode)
        or stat.S_ISBLK(unix_mode)
        or stat.S_ISFIFO(unix_mode)
        or stat.S_ISSOCK(unix_mode)
    ):
        reject(
            RejectionCode.DEVICE_OR_FIFO,
            "zip entry is a device, FIFO or socket",
            offending_path=path,
        )

    if info.is_dir() or stat.S_ISDIR(unix_mode):
        builder.add(path, ManifestKind.DIR, 0, stat.S_IMODE(unix_mode))
        return

    if unix_mode == 0 or stat.S_IFMT(unix_mode) == 0 or stat.S_ISREG(unix_mode):
        kind = ManifestKind.NESTED_ARCHIVE if looks_like_nested_archive(path) else ManifestKind.FILE
        builder.add(path, kind, info.file_size, stat.S_IMODE(unix_mode))
        return

    reject(
        RejectionCode.UNSUPPORTED_MEMBER_TYPE,
        "zip entry has an unsupported file type",
        offending_path=path,
    )


def _reject_zip_error(exc: BaseException) -> NoReturn:
    if "encrypt" in str(exc).lower():
        reject(RejectionCode.ENCRYPTED_ENTRY, "zip entry is encrypted")
    reject_archive_error(exc)
