"""Content-addressed download cache: keyed by the verified digest, re-verified on read."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from pkgwatch.fetch.cache import DownloadCache, ExpectedDigest, default_cache_dir, digest_matches
from pkgwatch.fetch.npm import expected_digest
from tests.support.npm_registry import dist_for


def _expected(payload: bytes, *, method: str = "integrity") -> ExpectedDigest:
    return expected_digest(dist_for(payload, method=method))


def test_a_miss_then_a_hit_returns_the_verified_bytes(tmp_path: Path) -> None:
    payload = b"synthetic tarball bytes"
    cache = DownloadCache(tmp_path / "cache")

    assert cache.get(_expected(payload)) is None

    cache.put(_expected(payload), payload)

    assert cache.get(_expected(payload)) == payload
    assert cache.path_for(_expected(payload)).is_file()
    assert (tmp_path / "cache") in cache.path_for(_expected(payload)).parents


def test_a_corrupt_entry_is_deleted_and_reported_as_a_miss(tmp_path: Path) -> None:
    payload = b"synthetic tarball bytes"
    cache = DownloadCache(tmp_path / "cache")
    expected = _expected(payload)
    cache.put(expected, payload)
    path = cache.path_for(expected)
    path.write_bytes(b"tampered")

    assert cache.get(expected) is None
    assert not path.exists()


def test_the_key_is_the_digest_not_a_url(tmp_path: Path) -> None:
    cache = DownloadCache(tmp_path / "cache")
    first = _expected(b"first payload")
    second = _expected(b"second payload")

    assert cache.path_for(first) != cache.path_for(second)


def test_bytes_that_do_not_match_the_key_are_never_stored(tmp_path: Path) -> None:
    payload = b"synthetic tarball bytes"
    cache = DownloadCache(tmp_path / "cache")
    expected = _expected(payload)

    with pytest.raises(ValueError, match="digest"):
        cache.put(expected, b"different bytes")

    assert not cache.path_for(expected).exists()
    assert cache.get(expected) is None


def test_a_shasum_only_entry_uses_the_sha1_key(tmp_path: Path) -> None:
    payload = b"legacy shasum payload"
    cache = DownloadCache(tmp_path / "cache")
    expected = _expected(payload, method="shasum")

    cache.put(expected, payload)

    assert cache.get(expected) == payload
    assert "sha1" in cache.path_for(expected).parts


@pytest.mark.parametrize(
    ("algorithm", "hexdigest_of"),
    [
        ("sha256", lambda data: hashlib.sha256(data).hexdigest()),
        ("blake2b_256", lambda data: hashlib.blake2b(data, digest_size=32).hexdigest()),
    ],
)
def test_pypi_algorithms_round_trip(
    tmp_path: Path, algorithm: str, hexdigest_of: Callable[[bytes], str]
) -> None:
    payload = b"synthetic pypi artifact bytes"
    cache = DownloadCache(tmp_path / "cache")
    expected = ExpectedDigest(
        method=f"digests.{algorithm}", algorithm=algorithm, hexdigest=hexdigest_of(payload)
    )

    cache.put(expected, payload)

    assert cache.get(expected) == payload
    assert algorithm in cache.path_for(expected).parts
    # A wrong digest for the same algorithm never matches.
    wrong = ExpectedDigest(method=expected.method, algorithm=algorithm, hexdigest="0" * 64)
    assert digest_matches(payload, wrong) is False
    assert digest_matches(payload, expected) is True


def test_key_is_fixed_length_and_fits_windows_paths() -> None:
    # A raw sha512 key was 128 chars; with a long Windows cache root that overflowed
    # MAX_PATH on os.replace. The derived key stays short regardless of algorithm.
    expected = _expected(b"synthetic tarball bytes")
    directory = Path("C:/long-cache") / ("d" * 180)
    path = DownloadCache(directory).path_for(expected)

    assert len(path.name) <= 40
    assert len(str(path)) < 260
    assert "sha512" in path.parts


def test_concurrent_puts_and_gets_return_the_verified_bytes(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    payload = b"synthetic tarball bytes"
    cache = DownloadCache(tmp_path / "cache")
    expected = _expected(payload)

    def worker(_: int) -> bytes | None:
        cache.put(expected, payload)
        return cache.get(expected)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(8)))

    assert all(result == payload for result in results)


def test_an_unknown_algorithm_is_rejected_not_downgraded_to_sha1(tmp_path: Path) -> None:
    cache = DownloadCache(tmp_path / "cache")
    unknown = ExpectedDigest(method="md5", algorithm="md5", hexdigest="0" * 32)

    with pytest.raises(ValueError, match="unsupported digest algorithm"):
        cache.put(unknown, b"synthetic tarball bytes")


def test_put_quietly_never_lets_cache_io_change_a_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: DownloadCache, expected: ExpectedDigest, data: bytes) -> None:
        raise OSError("cache disk full")

    monkeypatch.setattr(DownloadCache, "put", boom)
    cache = DownloadCache(tmp_path / "cache")

    cache.put_quietly(_expected(b"synthetic tarball bytes"), b"synthetic tarball bytes")


def test_the_default_cache_dir_is_absolute_and_can_be_overridden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PKGWATCH_CACHE_DIR", str(tmp_path / "redirected"))

    assert default_cache_dir() == tmp_path / "redirected"
    assert default_cache_dir().is_absolute()

    monkeypatch.delenv("PKGWATCH_CACHE_DIR")
    assert default_cache_dir().is_absolute()
