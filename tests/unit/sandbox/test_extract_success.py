from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from pkgwatch.models import ArchiveFormat, ManifestKind, SandboxLimits
from pkgwatch.sandbox import extract_archive
from tests.support.archives import Entry, make_tar


def test_extracts_files_dirs_and_hashes(tmp_path: Path) -> None:
    payload = b"print(1)\n"
    archive = make_tar(
        tmp_path / "pkg.tgz",
        [
            Entry("pkg/", kind="dir"),
            Entry("pkg/a.py", data=payload),
            Entry("pkg/sub/b.txt", data=b"hello"),
        ],
    )
    result = extract_archive(archive, tmp_path / "root", SandboxLimits())

    assert result.archive_format is ArchiveFormat.TAR_GZ
    assert (tmp_path / "root" / "pkg" / "a.py").read_bytes() == payload
    assert (tmp_path / "root" / "pkg" / "sub" / "b.txt").read_bytes() == b"hello"
    assert result.file_count == 2
    assert result.total_bytes == len(payload) + 5
    assert len(result.archive_sha256) == 64

    by_path = {entry.path: entry for entry in result.entries}
    assert by_path["pkg/a.py"].sha256 == hashlib.sha256(payload).hexdigest()
    assert by_path["pkg/a.py"].kind is ManifestKind.FILE
    assert by_path["pkg"].kind is ManifestKind.DIR
    assert [entry.path for entry in result.entries] == sorted(by_path)


def test_symlink_is_manifest_only(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "pkg.tgz",
        [
            Entry("pkg/a.py", data=b"x"),
            Entry("pkg/link.py", kind="symlink", linkname="a.py"),
        ],
    )
    result = extract_archive(archive, tmp_path / "root", SandboxLimits())
    by_path = {entry.path: entry for entry in result.entries}

    assert by_path["pkg/link.py"].kind is ManifestKind.SYMLINK
    assert by_path["pkg/link.py"].link_target == "pkg/a.py"
    assert by_path["pkg/link.py"].sha256 is None
    assert not (tmp_path / "root" / "pkg" / "link.py").exists()
    assert not os.path.islink(tmp_path / "root" / "pkg" / "link.py")


def test_hardlink_is_materialised_as_independent_copy(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "pkg.tgz",
        [
            Entry("pkg/a.py", data=b"shared"),
            Entry("pkg/hard.py", kind="hardlink", linkname="pkg/a.py"),
        ],
    )
    result = extract_archive(archive, tmp_path / "root", SandboxLimits())
    copied = tmp_path / "root" / "pkg" / "hard.py"

    assert copied.read_bytes() == b"shared"
    assert copied.stat().st_nlink == 1
    by_path = {entry.path: entry for entry in result.entries}
    assert by_path["pkg/hard.py"].kind is ManifestKind.HARDLINK
    assert by_path["pkg/hard.py"].link_target == "pkg/a.py"


def test_hardlink_chain_resolves(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "pkg.tgz",
        [
            Entry("a", data=b"chain"),
            Entry("b", kind="hardlink", linkname="a"),
            Entry("c", kind="hardlink", linkname="b"),
        ],
    )
    result = extract_archive(archive, tmp_path / "root", SandboxLimits())
    assert (tmp_path / "root" / "c").read_bytes() == b"chain"
    by_path = {entry.path: entry for entry in result.entries}
    assert by_path["c"].link_target == "a"


def test_nested_archive_is_recorded_not_extracted(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "pkg.tgz",
        [Entry("pkg/vendor.tgz", data=b"not really an archive")],
    )
    result = extract_archive(archive, tmp_path / "root", SandboxLimits())
    by_path = {entry.path: entry for entry in result.entries}

    assert by_path["pkg/vendor.tgz"].kind is ManifestKind.NESTED_ARCHIVE
    assert (tmp_path / "root" / "pkg" / "vendor.tgz").read_bytes() == b"not really an archive"
    assert not (tmp_path / "root" / "pkg" / "vendor").exists()


def test_empty_archive_succeeds(tmp_path: Path) -> None:
    archive = make_tar(tmp_path / "empty.tgz", [])
    result = extract_archive(archive, tmp_path / "root", SandboxLimits())
    assert result.file_count == 0
    assert result.total_bytes == 0
    assert result.entries == ()
    assert (tmp_path / "root").is_dir()


def test_manifest_is_deterministic(tmp_path: Path) -> None:
    entries = [
        Entry("pkg/b.py", data=b"b"),
        Entry("pkg/a.py", data=b"a"),
        Entry("pkg/sub/c.py", data=b"c"),
    ]
    archive = make_tar(tmp_path / "pkg.tgz", entries)
    first = extract_archive(archive, tmp_path / "root1", SandboxLimits())
    second = extract_archive(archive, tmp_path / "root2", SandboxLimits())

    assert first.archive_sha256 == second.archive_sha256
    assert [entry.model_dump() for entry in first.entries] == [
        entry.model_dump() for entry in second.entries
    ]


def test_non_empty_target_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "root"
    target.mkdir()
    (target / "keep.txt").write_bytes(b"keep")
    archive = make_tar(tmp_path / "pkg.tgz", [Entry("pkg/a.py", data=b"x")])

    with pytest.raises(FileExistsError):
        extract_archive(archive, target, SandboxLimits())
    assert (target / "keep.txt").read_bytes() == b"keep"
    assert not (target / "pkg").exists()


def test_target_symlink_is_replaced_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    target = tmp_path / "root"
    try:
        target.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip(
            "OS denies symlink creation (Windows Developer Mode or admin required); "
            "the replaced-not-followed property cannot be exercised here"
        )

    archive = make_tar(tmp_path / "pkg.tgz", [Entry("pkg/a.py", data=b"x")])
    extract_archive(archive, target, SandboxLimits())

    assert not (outside / "pkg").exists()
    assert (target / "pkg" / "a.py").read_bytes() == b"x"
    assert not target.is_symlink()
