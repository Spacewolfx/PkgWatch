"""Member-name normalisation and link-target checks.

All checks run on the *archive-declared* name before anything is written, and the
result is a POSIX relative path with no empty, ``.`` or ``..`` components.
"""

from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path

from pkgwatch.models import RejectionCode, SandboxLimits
from pkgwatch.sandbox.errors import ArchiveRejected, reject

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_ILLEGAL_CHARS = re.compile(r'[<>:"|?*]')
# NTFS component limit; not policy, so it is a constant rather than a config knob.
_MAX_COMPONENT_LEN = 255
# Windows full-path limit (including the terminating null) for non-extended paths.
_WINDOWS_MAX_PATH = 260
_RESERVED_BASENAMES = frozenset(
    {"con", "prn", "aux", "nul", "clock$", "conin$", "conout$"}
    | {f"com{index}" for index in range(1, 10)}
    | {f"lpt{index}" for index in range(1, 10)}
)


def _utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _component_too_long(part: str) -> bool:
    # POSIX caps a component at 255 bytes; NTFS at 255 UTF-16 units. Reject when
    # either measure is exceeded so extraction never hits an OS name-length error.
    return len(part.encode("utf-8")) > _MAX_COMPONENT_LEN or _utf16_len(part) > _MAX_COMPONENT_LEN


def normalize_member_name(name: str, limits: SandboxLimits) -> str:
    """Return a safe POSIX relative path, or raise ``ArchiveRejected``."""
    if not name:
        reject(RejectionCode.INVALID_NAME, "empty member name")

    if name.startswith(("//", "\\\\")):
        reject(
            RejectionCode.DRIVE_OR_UNC_PATH,
            "member name is a UNC path",
            offending_path=name,
        )
    if _DRIVE_RE.match(name):
        reject(
            RejectionCode.DRIVE_OR_UNC_PATH,
            "member name starts with a drive letter",
            offending_path=name,
        )
    if name.startswith("/"):
        reject(
            RejectionCode.ABSOLUTE_PATH,
            "member name is absolute",
            offending_path=name,
        )
    if "\\" in name:
        reject(
            RejectionCode.BACKSLASH_IN_NAME,
            "member name contains a backslash",
            offending_path=name,
        )
    if _CONTROL_RE.search(name):
        reject(
            RejectionCode.NAME_HAS_CONTROL_CHARS,
            "member name contains control characters",
            offending_path=name,
        )

    raw_parts = name.split("/")
    if ".." in raw_parts:
        reject(
            RejectionCode.PATH_TRAVERSAL,
            "member name contains a parent-directory component",
            offending_path=name,
        )
    parts = [part for part in raw_parts if part not in ("", ".")]
    if not parts:
        reject(RejectionCode.INVALID_NAME, "member name has no path components")

    for part in parts:
        if _WINDOWS_ILLEGAL_CHARS.search(part):
            reject(
                RejectionCode.WINDOWS_ILLEGAL_NAME,
                "member name contains a character Windows reserves",
                offending_path=name,
            )
        if _component_too_long(part):
            reject(
                RejectionCode.PATH_TOO_LONG,
                "member name component exceeds the filesystem limit",
                offending_path=name,
                limit_name="max_component_len",
                limit_value=float(_MAX_COMPONENT_LEN),
                observed_value=float(max(len(part.encode("utf-8")), _utf16_len(part))),
            )
        if part.endswith((" ", ".")):
            reject(
                RejectionCode.WINDOWS_ILLEGAL_NAME,
                "member name has a trailing space or dot",
                offending_path=name,
            )
        stem = part.split(".", 1)[0].lower()
        if stem in _RESERVED_BASENAMES:
            reject(
                RejectionCode.WINDOWS_ILLEGAL_NAME,
                "member name is a Windows reserved device name",
                offending_path=name,
            )

    relative = "/".join(parts)
    if len(relative) > limits.max_entry_path_len:
        reject(
            RejectionCode.PATH_TOO_LONG,
            "member path exceeds max_entry_path_len",
            offending_path=name,
            limit_name="max_entry_path_len",
            limit_value=float(limits.max_entry_path_len),
            observed_value=float(len(relative)),
        )
    if len(parts) > limits.max_entry_depth:
        reject(
            RejectionCode.DEPTH_EXCEEDED,
            "member path exceeds max_entry_depth",
            offending_path=name,
            limit_name="max_entry_depth",
            limit_value=float(limits.max_entry_depth),
            observed_value=float(len(parts)),
        )
    return relative


def resolve_symlink_target(member_path: str, target: str, limits: SandboxLimits) -> str:
    """Validate a symlink target and return it as a root-relative POSIX path."""
    if not target:
        reject(
            RejectionCode.SYMLINK_OUTSIDE_TARGET,
            "symlink has an empty target",
            offending_path=member_path,
        )
    if _CONTROL_RE.search(target):
        reject(
            RejectionCode.NAME_HAS_CONTROL_CHARS,
            "symlink target contains control characters",
            offending_path=member_path,
        )
    if len(target) > limits.max_entry_path_len:
        reject(
            RejectionCode.SYMLINK_TARGET_TOO_LONG,
            "symlink target exceeds max_entry_path_len",
            offending_path=member_path,
            limit_name="max_entry_path_len",
            limit_value=float(limits.max_entry_path_len),
            observed_value=float(len(target)),
        )
    if target.startswith(("/", "\\")) or _DRIVE_RE.match(target):
        reject(
            RejectionCode.SYMLINK_ABSOLUTE_TARGET,
            "symlink target is absolute",
            offending_path=member_path,
        )
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(member_path), target))
    if joined == ".." or joined.startswith("../") or posixpath.isabs(joined):
        reject(
            RejectionCode.SYMLINK_OUTSIDE_TARGET,
            "symlink target escapes the extraction root",
            offending_path=member_path,
        )
    return joined


def normalize_hardlink_target(member_path: str, target: str, limits: SandboxLimits) -> str:
    """Hardlink names are archive-root relative; reuse the member-name rules."""
    try:
        return normalize_member_name(target, limits)
    except ArchiveRejected:
        reject(
            RejectionCode.HARDLINK_OUTSIDE_TARGET,
            "hardlink target is not a safe in-archive path",
            offending_path=member_path,
        )


def within_root(root: Path, relative: str) -> Path:
    """Join a validated relative path onto ``root`` and prove it stays inside."""
    root = Path(os.path.abspath(root))
    candidate = Path(os.path.normpath(root / relative))
    if candidate == root or not candidate.is_relative_to(root):
        reject(
            RejectionCode.EXTRACTION_ROOT_ESCAPE,
            "resolved destination escapes the extraction root",
            offending_path=relative,
        )
    if os.name == "nt" and len(str(candidate)) >= _WINDOWS_MAX_PATH:
        reject(
            RejectionCode.PATH_TOO_LONG,
            "destination path exceeds the Windows MAX_PATH limit",
            offending_path=relative,
            limit_name="windows_max_path",
            limit_value=float(_WINDOWS_MAX_PATH),
            observed_value=float(len(str(candidate))),
        )
    return candidate
