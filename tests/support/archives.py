"""Synthetic archive builders. Fixtures are generated, never committed binaries."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Entry:
    name: str
    data: bytes = b""
    kind: str = "file"
    linkname: str = ""
    mode: int = 0o644


def make_tar(path: Path, entries: list[Entry], *, gzip: bool = True) -> Path:
    mode = "w:gz" if gzip else "w"
    with tarfile.open(path, mode, format=tarfile.PAX_FORMAT) as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.mode = entry.mode
            info.mtime = 0
            if entry.kind == "file":
                info.size = len(entry.data)
                archive.addfile(info, io.BytesIO(entry.data))
                continue
            info.size = 0
            if entry.kind == "dir":
                info.type = tarfile.DIRTYPE
            elif entry.kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = entry.linkname
            elif entry.kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = entry.linkname
            elif entry.kind == "chr":
                info.type = tarfile.CHRTYPE
                info.devmajor = 1
                info.devminor = 3
            elif entry.kind == "blk":
                info.type = tarfile.BLKTYPE
            elif entry.kind == "fifo":
                info.type = tarfile.FIFOTYPE
            elif entry.kind == "other":
                info.type = b"Z"
            else:
                raise AssertionError(f"unknown entry kind: {entry.kind}")
            archive.addfile(info)
    return path


def make_zip(path: Path, entries: list[Entry]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            info = zipfile.ZipInfo(entry.name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            if entry.kind == "dir":
                info.external_attr = ((stat.S_IFDIR | 0o755) << 16) | 0x10
                archive.writestr(info, b"")
            elif entry.kind == "symlink":
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, entry.linkname.encode("utf-8"))
            elif entry.kind in {"chr", "blk", "fifo"}:
                bits = {
                    "chr": stat.S_IFCHR,
                    "blk": stat.S_IFBLK,
                    "fifo": stat.S_IFIFO,
                }[entry.kind]
                info.external_attr = (bits | 0o644) << 16
                archive.writestr(info, b"")
            else:
                info.external_attr = (stat.S_IFREG | entry.mode) << 16
                archive.writestr(info, entry.data)
    return path


def mark_encrypted(path: Path) -> Path:
    """Set the encrypted bit on every local and central zip header."""
    data = bytearray(path.read_bytes())
    patched = 0
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = data.find(signature)
        while start != -1:
            data[start + flag_offset] |= 0x01
            patched += 1
            start = data.find(signature, start + 4)
    if patched < 2:
        raise AssertionError("could not locate zip headers to patch")
    path.write_bytes(bytes(data))
    return path
