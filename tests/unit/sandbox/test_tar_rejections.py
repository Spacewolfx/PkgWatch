from __future__ import annotations

import time
from pathlib import Path

import pytest

from pkgwatch.models import ArchiveFormat, RejectionCode, SandboxLimits
from pkgwatch.sandbox import ArchiveRejected, extract_archive
from pkgwatch.sandbox.extract import sha256_file, sniff_archive
from tests.support.archives import Entry, make_tar
from tests.unit.sandbox.helpers import assert_rejected


def test_absolute_path(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("/etc/passwd", b"x")], RejectionCode.ABSOLUTE_PATH)


def test_path_traversal(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("../../evil.py", b"x")], RejectionCode.PATH_TRAVERSAL)


def test_drive_letter(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("C:/Windows/evil.py", b"x")], RejectionCode.DRIVE_OR_UNC_PATH)


def test_unc_path(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path, [Entry("//server/share/evil.py", b"x")], RejectionCode.DRIVE_OR_UNC_PATH
    )


def test_backslash_in_name(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("pkg\\evil.py", b"x")], RejectionCode.BACKSLASH_IN_NAME)


def test_control_characters(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path, [Entry("pkg/\x01evil.py", b"x")], RejectionCode.NAME_HAS_CONTROL_CHARS
    )


@pytest.mark.parametrize("name", ["CON", "aux.txt", "com1.log", "trail.", "trail "])
def test_windows_illegal_names(tmp_path: Path, name: str) -> None:
    assert_rejected(tmp_path, [Entry(f"pkg/{name}", b"x")], RejectionCode.WINDOWS_ILLEGAL_NAME)


def test_invalid_name(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry(".", b"x")], RejectionCode.INVALID_NAME)


def test_case_collision(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/Foo.py", b"a"), Entry("pkg/foo.py", b"b")],
        RejectionCode.CASE_COLLISION,
    )


def test_duplicate_member(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/a.py", b"a"), Entry("pkg/a.py", b"b")],
        RejectionCode.DUPLICATE_MEMBER,
    )


def test_path_conflict(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/a", b"a"), Entry("pkg/a/b.py", b"b")],
        RejectionCode.PATH_CONFLICT,
    )


def test_depth_limit(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("a/b/c.txt", b"x")],
        RejectionCode.DEPTH_EXCEEDED,
        max_entry_depth=2,
    )


def test_path_too_long(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("abcdefghijk.py", b"x")],
        RejectionCode.PATH_TOO_LONG,
        max_entry_path_len=10,
    )


def test_file_count_limit(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("a", b"1"), Entry("b", b"2"), Entry("c", b"3")],
        RejectionCode.FILE_COUNT_EXCEEDED,
        max_file_count=2,
    )


def test_single_file_too_large(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("big.bin", b"x" * 100)],
        RejectionCode.FILE_TOO_LARGE,
        max_single_file_bytes=10,
    )


def test_total_uncompressed_limit(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("a", b"x" * 100), Entry("b", b"y" * 100)],
        RejectionCode.TOTAL_UNCOMPRESSED_EXCEEDED,
        max_total_uncompressed_bytes=150,
    )


def test_compression_ratio_limit(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("zeros.bin", b"\x00" * (2 * 1024 * 1024))],
        RejectionCode.COMPRESSION_RATIO_EXCEEDED,
        max_compression_ratio=2.0,
    )


def test_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_monotonic() -> float:
        calls["count"] += 1
        return 0.0 if calls["count"] == 1 else 10.0

    monkeypatch.setattr(time, "monotonic", fake_monotonic)
    archive = make_tar(tmp_path / "pkg.tgz", [Entry("a.py", b"x")])
    with pytest.raises(ArchiveRejected) as excinfo:
        extract_archive(
            archive,
            tmp_path / "root",
            SandboxLimits(extract_deadline_seconds=1.0),
        )
    assert excinfo.value.rejection.reason_code is RejectionCode.DEADLINE_EXCEEDED


def test_character_device(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("dev", kind="chr")], RejectionCode.DEVICE_OR_FIFO)


def test_block_device(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("dev", kind="blk")], RejectionCode.DEVICE_OR_FIFO)


def test_fifo(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("pipe", kind="fifo")], RejectionCode.DEVICE_OR_FIFO)


def test_unsupported_member_type(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("weird", kind="other")], RejectionCode.UNSUPPORTED_MEMBER_TYPE)


def test_symlink_outside_target(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/link", kind="symlink", linkname="../../../etc/passwd")],
        RejectionCode.SYMLINK_OUTSIDE_TARGET,
    )


def test_symlink_absolute_target(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/link", kind="symlink", linkname="/etc/passwd")],
        RejectionCode.SYMLINK_ABSOLUTE_TARGET,
    )


def test_symlink_target_too_long(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("link", kind="symlink", linkname="a" * 20)],
        RejectionCode.SYMLINK_TARGET_TOO_LONG,
        max_entry_path_len=10,
    )


def test_hardlink_outside_target(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/link", kind="hardlink", linkname="../outside")],
        RejectionCode.HARDLINK_OUTSIDE_TARGET,
    )


def test_hardlink_missing_target(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/link", kind="hardlink", linkname="pkg/missing.py")],
        RejectionCode.HARDLINK_MISSING_TARGET,
    )


def test_hardlink_cycle(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [
            Entry("a", kind="hardlink", linkname="b"),
            Entry("b", kind="hardlink", linkname="a"),
        ],
        RejectionCode.HARDLINK_CYCLE,
    )


def test_parent_is_symlink(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [
            Entry("lib", kind="symlink", linkname="real"),
            Entry("lib/x.py", b"x"),
        ],
        RejectionCode.PARENT_IS_SYMLINK,
    )


def test_artifact_too_large(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("a.py", b"x" * 100)],
        RejectionCode.ARTIFACT_TOO_LARGE,
        max_artifact_bytes=10,
    )


def test_unsupported_format(tmp_path: Path) -> None:
    archive = tmp_path / "pkg.bin"
    archive.write_bytes(b"this is not an archive at all")
    with pytest.raises(ArchiveRejected) as excinfo:
        extract_archive(archive, tmp_path / "root", SandboxLimits())
    assert excinfo.value.rejection.reason_code is RejectionCode.ARCHIVE_FORMAT_UNSUPPORTED


def test_truncated_archive(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "pkg.tgz", [Entry("pkg/a.py", b"x" * 4096)])
    data = archive.read_bytes()
    archive.write_bytes(data[: len(data) // 2])
    with pytest.raises(ArchiveRejected) as excinfo:
        extract_archive(archive, tmp_path / "root", SandboxLimits())
    assert excinfo.value.rejection.reason_code is RejectionCode.ARCHIVE_TRUNCATED


def test_sniff_and_hash(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "pkg.tgz", [Entry("a.py", b"x")])
    assert sniff_archive(archive) is ArchiveFormat.TAR_GZ
    assert sha256_file(archive) == sha256_file(archive)
    assert len(sha256_file(archive)) == 64
