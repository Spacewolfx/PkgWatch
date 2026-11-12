from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pkgwatch.models import RejectionCode, SandboxLimits
from pkgwatch.sandbox.errors import ArchiveRejected
from pkgwatch.sandbox.names import normalize_member_name, within_root

ALPHABET = "abcXYZ0123/._-\\: ~@"


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("", RejectionCode.INVALID_NAME),
        (".", RejectionCode.INVALID_NAME),
        ("/etc/passwd", RejectionCode.ABSOLUTE_PATH),
        ("//server/share/x", RejectionCode.DRIVE_OR_UNC_PATH),
        ("\\\\server\\share\\x", RejectionCode.DRIVE_OR_UNC_PATH),
        ("C:/Windows/x", RejectionCode.DRIVE_OR_UNC_PATH),
        ("c:evil", RejectionCode.DRIVE_OR_UNC_PATH),
        ("dir\\file.txt", RejectionCode.BACKSLASH_IN_NAME),
        ("\x01evil", RejectionCode.NAME_HAS_CONTROL_CHARS),
        ("../x", RejectionCode.PATH_TRAVERSAL),
        ("a/../../etc/passwd", RejectionCode.PATH_TRAVERSAL),
        ("a/..", RejectionCode.PATH_TRAVERSAL),
        ("CON", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("aux.txt", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("com1.log", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("lpt9", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("trail.", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("trail ", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("0:", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("a?b.py", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("a<b.py", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ('a"b.py', RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("a|b.py", RejectionCode.WINDOWS_ILLEGAL_NAME),
        ("a*b.py", RejectionCode.WINDOWS_ILLEGAL_NAME),
    ],
)
def test_rejects_unsafe_names(name: str, code: RejectionCode, limits: SandboxLimits) -> None:
    with pytest.raises(ArchiveRejected) as excinfo:
        normalize_member_name(name, limits)
    assert excinfo.value.rejection.reason_code is code


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("./a/b", "a/b"),
        ("a//b/", "a/b"),
        ("a/./b", "a/b"),
        ("a-b_c/d.e", "a-b_c/d.e"),
        (".hidden/x", ".hidden/x"),
        (
            "\u00fcn\u00efcode/\u0444\u0430\u0439\u043b.py",
            "\u00fcn\u00efcode/\u0444\u0430\u0439\u043b.py",
        ),
    ],
)
def test_normalises_safe_names(raw: str, expected: str, limits: SandboxLimits) -> None:
    assert normalize_member_name(raw, limits) == expected


def test_path_length_limit() -> None:
    limits = SandboxLimits(max_entry_path_len=5)
    with pytest.raises(ArchiveRejected) as excinfo:
        normalize_member_name("abcdefg", limits)
    assert excinfo.value.rejection.reason_code is RejectionCode.PATH_TOO_LONG


def test_depth_limit() -> None:
    limits = SandboxLimits(max_entry_depth=2)
    with pytest.raises(ArchiveRejected) as excinfo:
        normalize_member_name("a/b/c", limits)
    assert excinfo.value.rejection.reason_code is RejectionCode.DEPTH_EXCEEDED


@given(name=st.text(alphabet=ALPHABET, max_size=40))
def test_normalised_paths_always_stay_inside_the_root(name: str, tmp_path: Path) -> None:
    limits = SandboxLimits()
    try:
        relative = normalize_member_name(name, limits)
    except ArchiveRejected:
        return
    destination = within_root(tmp_path, relative)
    assert destination.is_relative_to(tmp_path)
    assert ".." not in relative.split("/")


def test_component_length_counts_utf8_bytes_and_utf16_units() -> None:
    # 131 characters, but 515 UTF-8 bytes and 259 UTF-16 units: both filesystem
    # limits (255 bytes on POSIX, 255 UTF-16 units on NTFS) are exceeded.
    limits = SandboxLimits()
    name = "pkg/" + "\U0001f600" * 128 + ".py"
    with pytest.raises(ArchiveRejected) as excinfo:
        normalize_member_name(name, limits)
    assert excinfo.value.rejection.reason_code is RejectionCode.PATH_TOO_LONG


def test_component_length_counts_multibyte_bmp_characters() -> None:
    limits = SandboxLimits()
    name = "pkg/" + "é" * 200  # 200 characters but 400 UTF-8 bytes
    with pytest.raises(ArchiveRejected) as excinfo:
        normalize_member_name(name, limits)
    assert excinfo.value.rejection.reason_code is RejectionCode.PATH_TOO_LONG


def test_component_at_the_byte_limit_is_accepted() -> None:
    limits = SandboxLimits()
    name = "pkg/" + "a" * 252 + ".py"  # exactly 255 bytes / UTF-16 units
    assert normalize_member_name(name, limits) == name


@pytest.mark.skipif(os.name != "nt", reason="Windows MAX_PATH limit is platform-specific")
def test_destination_over_windows_max_path_is_rejected(tmp_path: Path) -> None:
    limits = SandboxLimits()
    relative = normalize_member_name("a" * 120 + "/" + "b" * 120 + "/" + "c" * 8, limits)
    with pytest.raises(ArchiveRejected) as excinfo:
        within_root(tmp_path, relative)
    assert excinfo.value.rejection.reason_code is RejectionCode.PATH_TOO_LONG
