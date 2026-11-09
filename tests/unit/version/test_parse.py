"""Unit tests for the SPEC §6.4 version parser: acceptance and canonicalisation."""

from __future__ import annotations

import pytest

from pkgwatch.models import Ecosystem
from pkgwatch.version import ParsedVersion, UnsupportedVersion, parse


@pytest.mark.parametrize(
    "text",
    ["1.2.3", "0.0.0", "1.2.3-alpha.1", "1.2.3-0a", "1.2.3+build.5", "1.2.3-rc.1+meta"],
)
def test_npm_accepts_exact_semver(text: str) -> None:
    parsed = parse(Ecosystem.NPM, text)
    assert parsed.ecosystem is Ecosystem.NPM
    assert parsed.text == text


@pytest.mark.parametrize(
    "text",
    ["", "1.2", "1", "v1.2.3", "1.2.3-", "1.2.3+", "latest", "^1.2.3", "1.2.x"],
)
def test_npm_rejects_ranges_tags_and_garbage(text: str) -> None:
    with pytest.raises(UnsupportedVersion):
        parse(Ecosystem.NPM, text)


def test_npm_canonical_is_verbatim() -> None:
    assert parse(Ecosystem.NPM, "1.2.3+build").canonical == "1.2.3+build"


@pytest.mark.parametrize(
    "text",
    [
        "1.0",
        "1.0.0",
        "1.0.post1",
        "1.0a1",
        "1.0b2",
        "1.0rc1",
        "1.0.dev3",
        "2!1.0",
        "1.0+local.1",
        "1.0a1.post2",
        "2026.11.9",
    ],
)
def test_pypi_accepts_pep440(text: str) -> None:
    parsed = parse(Ecosystem.PYPI, text)
    assert parsed.ecosystem is Ecosystem.PYPI


@pytest.mark.parametrize("text", ["", "foo", "1.0+", "1.0-", "v", "1.0.0.0.0.0.0+"])
def test_pypi_rejects_garbage(text: str) -> None:
    with pytest.raises(UnsupportedVersion):
        parse(Ecosystem.PYPI, text)


@pytest.mark.parametrize(
    ("text", "canonical"),
    [
        ("1.02.3", "1.2.3"),
        ("1.0.0", "1.0.0"),
        ("1.0-ALPHA1", "1.0a1"),
        ("1.0.alpha-1", "1.0a1"),
        ("1.0_rc1", "1.0rc1"),
        ("1.0-rc.2", "1.0rc2"),
        ("1.0.post", "1.0.post0"),
        ("1.0-1", "1.0.post1"),
        ("1.0.dev", "1.0.dev0"),
        ("1.0+LOCAL.1", "1.0+local.1"),
        ("v1.0", "1.0"),
    ],
)
def test_pypi_canonical_normalizes(text: str, canonical: str) -> None:
    assert parse(Ecosystem.PYPI, canonical).canonical == canonical
    assert parse(Ecosystem.PYPI, text).canonical == canonical


def test_crates_is_unsupported_in_this_milestone() -> None:
    with pytest.raises(UnsupportedVersion):
        parse(Ecosystem.CRATES, "1.2.3")


def test_parse_returns_frozen_dataclass() -> None:
    parsed = parse(Ecosystem.NPM, "1.0.0")
    assert isinstance(parsed, ParsedVersion)
    with pytest.raises(AttributeError):
        parsed.text = "2.0.0"  # type: ignore[misc]
