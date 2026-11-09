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


def test_the_default_cache_dir_is_absolute_and_can_be_overridden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PKGWATCH_CACHE_DIR", str(tmp_path / "redirected"))

    assert default_cache_dir() == tmp_path / "redirected"
    assert default_cache_dir().is_absolute()

    monkeypatch.delenv("PKGWATCH_CACHE_DIR")
    assert default_cache_dir().is_absolute()
