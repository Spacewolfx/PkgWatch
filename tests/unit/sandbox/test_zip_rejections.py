from __future__ import annotations

from pathlib import Path

import pytest

from pkgwatch.models import ArchiveFormat, RejectionCode, SandboxLimits
from pkgwatch.sandbox import ArchiveRejected, extract_archive
from tests.support.archives import Entry, make_zip, mark_encrypted
from tests.unit.sandbox.helpers import assert_rejected


def test_zip_path_traversal(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path, [Entry("../evil.py", b"x")], RejectionCode.PATH_TRAVERSAL, as_zip=True
    )


def test_zip_symlink_outside_target(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/link", kind="symlink", linkname="../../../etc/passwd")],
        RejectionCode.SYMLINK_OUTSIDE_TARGET,
        as_zip=True,
    )


def test_zip_device(tmp_path: Path) -> None:
    assert_rejected(tmp_path, [Entry("dev", kind="chr")], RejectionCode.DEVICE_OR_FIFO, as_zip=True)


def test_zip_case_collision(tmp_path: Path) -> None:
    assert_rejected(
        tmp_path,
        [Entry("pkg/Foo.py", b"a"), Entry("pkg/foo.py", b"b")],
        RejectionCode.CASE_COLLISION,
        as_zip=True,
    )


def test_zip_encrypted_entry(tmp_path: Path) -> None:
    archive = mark_encrypted(make_zip(tmp_path / "pkg.zip", [Entry("pkg/a.py", b"x")]))
    with pytest.raises(ArchiveRejected) as excinfo:
        extract_archive(archive, tmp_path / "root", SandboxLimits())
    assert excinfo.value.rejection.reason_code is RejectionCode.ENCRYPTED_ENTRY
    assert not (tmp_path / "root").exists()


def test_zip_success(tmp_path: Path) -> None:
    archive = make_zip(
        tmp_path / "pkg.zip",
        [
            Entry("pkg/", kind="dir"),
            Entry("pkg/a.py", data=b"print(1)\n"),
        ],
    )
    result = extract_archive(archive, tmp_path / "root", SandboxLimits())
    assert result.archive_format is ArchiveFormat.ZIP
    assert (tmp_path / "root" / "pkg" / "a.py").read_bytes() == b"print(1)\n"
    assert result.file_count == 1
