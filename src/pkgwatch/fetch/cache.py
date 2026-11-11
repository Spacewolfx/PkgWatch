"""Content-addressed artifact cache for ``pkgwatch compare`` and ``pkgwatch lock`` (SPEC §9.1).

An entry is keyed by the digest the registry advertises and the bytes were verified
against, so a cache hit is byte-identical to a fresh download. Every read hashes the file
again: a corrupt or truncated entry is deleted and treated as a miss, never trusted.
The default location is the operating system's user cache directory, never the repository.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import tempfile
from dataclasses import dataclass
from pathlib import Path

CACHE_DIR_ENV = "PKGWATCH_CACHE_DIR"


@dataclass(frozen=True)
class ExpectedDigest:
    """A registry digest, safe to use as a cache key and to re-verify bytes against."""

    method: str
    algorithm: str
    hexdigest: str


def digest_matches(data: bytes, expected: ExpectedDigest) -> bool:
    if expected.algorithm == "sha512":
        return hashlib.sha512(data).hexdigest() == expected.hexdigest
    if expected.algorithm == "sha256":
        return hashlib.sha256(data).hexdigest() == expected.hexdigest
    if expected.algorithm == "blake2b_256":
        return hashlib.blake2b(data, digest_size=32).hexdigest() == expected.hexdigest
    return hashlib.sha1(data).hexdigest() == expected.hexdigest  # noqa: S324 - legacy npm shasum


class DownloadCache:
    """On-disk cache of verified tarballs, addressed by their digest."""

    def __init__(self, directory: Path) -> None:
        self._directory = directory

    @property
    def directory(self) -> Path:
        return self._directory

    def path_for(self, expected: ExpectedDigest) -> Path:
        digest = expected.hexdigest
        return self._directory / expected.algorithm / digest[:2] / f"{digest}.tgz"

    def get(self, expected: ExpectedDigest) -> bytes | None:
        path = self.path_for(expected)
        try:
            data = path.read_bytes()
        except OSError:
            return None
        if digest_matches(data, expected):
            return data
        with contextlib.suppress(OSError):
            path.unlink()
        return None

    def put(self, expected: ExpectedDigest, data: bytes) -> None:
        if not digest_matches(data, expected):
            raise ValueError("cache entry does not match its digest")
        path = self.path_for(expected)
        path.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=path.parent, prefix=".pkgwatch-")
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
            os.replace(temporary, path)
        except OSError:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
            raise


def default_cache_dir() -> Path:
    """The user cache directory for this OS; an env override is for tests and operators."""
    override = os.environ.get(CACHE_DIR_ENV)
    if override:
        return Path(override).expanduser().resolve()
    home = Path.home()
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "pkgwatch" / "cache" if base else home / ".cache" / "pkgwatch"
    if system == "Darwin":
        return home / "Library" / "Caches" / "pkgwatch"
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base) if base else home / ".cache") / "pkgwatch"
