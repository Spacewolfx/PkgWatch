"""Content-addressed artifact cache for ``pkgwatch compare`` and ``pkgwatch lock`` (SPEC §9.1).

An entry is keyed by the digest the registry advertises and the bytes were verified
against, so a cache hit is byte-identical to a fresh download. Every read hashes the file
again: a corrupt or truncated entry is deleted and treated as a miss, never trusted.
The default location is the operating system's user cache directory, never the repository.

The on-disk key is a fixed 32-hex digest of the registry digest, not the digest itself:
a raw sha512 filename is 128 characters and overflows Windows MAX_PATH in real cache
directories. The algorithm stays as a directory component for readability.

Caching is an optional optimisation. ``put_quietly`` and ``get`` never let cache I/O change
an analysis verdict; ``put`` stays strict for callers and tests that want the error.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CACHE_DIR_ENV = "PKGWATCH_CACHE_DIR"

# Only these algorithms may be used as verification or cache keys. An unrecognised
# algorithm must never fall through to SHA-1: that would be a silent digest downgrade.
_ALGORITHMS = frozenset({"sha1", "sha256", "sha512", "blake2b_256"})
_HASH_CHUNK_BYTES = 64 * 1024
_KEY_LENGTH = 32


@dataclass(frozen=True)
class ExpectedDigest:
    """A registry digest, safe to use as a cache key and to re-verify bytes against."""

    method: str
    algorithm: str
    hexdigest: str


def _hasher(algorithm: str) -> Any:
    """A hashlib object for an allow-listed algorithm; anything else is a hard error."""
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"unsupported digest algorithm: {algorithm!r}")
    if algorithm == "sha1":
        return hashlib.sha1()  # noqa: S324 - npm's legacy dist.shasum only
    if algorithm == "sha256":
        return hashlib.sha256()
    if algorithm == "sha512":
        return hashlib.sha512()
    return hashlib.blake2b(digest_size=32)


def digest_matches(data: bytes, expected: ExpectedDigest) -> bool:
    hasher = _hasher(expected.algorithm)
    hasher.update(data)
    return bool(hasher.hexdigest() == expected.hexdigest)


def digest_matches_file(path: Path, expected: ExpectedDigest) -> bool:
    """Hash a file in bounded chunks, so verification does not double memory use."""
    hasher = _hasher(expected.algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(_HASH_CHUNK_BYTES), b""):
            hasher.update(chunk)
    return bool(hasher.hexdigest() == expected.hexdigest)


@dataclass(frozen=True)
class DownloadCache:
    """On-disk cache of verified tarballs, addressed by their digest."""

    _directory: Path
    _guard: Any = field(default_factory=threading.Lock, repr=False, compare=False)
    _keys: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def directory(self) -> Path:
        return self._directory

    def path_for(self, expected: ExpectedDigest) -> Path:
        # Hashing the registry digest gives a fixed-length, hex-only key. ExpectedDigest
        # values are constructed by validated fetch code, but no package text is used
        # as a path component here.
        key = hashlib.sha256(expected.hexdigest.encode("ascii")).hexdigest()[:_KEY_LENGTH]
        return self._directory / expected.algorithm / key[:2] / f"{key}.tgz"

    def _key_lock(self, expected: ExpectedDigest) -> Any:
        name = f"{expected.algorithm}/{expected.hexdigest}"
        with self._guard:
            lock = self._keys.get(name)
            if lock is None:
                lock = threading.Lock()
                self._keys[name] = lock
            return lock

    def get(self, expected: ExpectedDigest) -> bytes | None:
        path = self.path_for(expected)
        # A cache is replaceable: any I/O problem is a miss, never a failed analysis.
        # The bytes themselves are still verified before being returned.
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
        with self._key_lock(expected):
            # Another worker may have written the same verified bytes while we waited.
            if path.is_file() and digest_matches_file(path, expected):
                return
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

    def put_quietly(self, expected: ExpectedDigest, data: bytes) -> None:
        """Best-effort cache write: I/O errors stay invisible to the analysis verdict."""
        try:
            self.put(expected, data)
        except OSError:
            return


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
