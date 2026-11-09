"""Unit tests for version precedence comparison (SPEC §6.4)."""

from __future__ import annotations

import pytest

from pkgwatch.models import Ecosystem
from pkgwatch.version import UnsupportedVersion, compare, parse


def npm(text: str):  # type: ignore[no-untyped-def]
    return parse(Ecosystem.NPM, text)


def pypi(text: str):  # type: ignore[no-untyped-def]
    return parse(Ecosystem.PYPI, text)


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.0", "1.0.1"),
        ("1.0.1", "1.1.0"),
        ("1.1.0", "2.0.0"),
        ("1.0.0-alpha", "1.0.0-alpha.1"),
        ("1.0.0-alpha.1", "1.0.0-beta"),
        ("1.0.0-beta", "1.0.0"),
        ("1.0.0-alpha.2", "1.0.0-alpha.10"),
        ("1.0.0-1", "1.0.0-a"),  # numeric identifiers sort before alphanumeric
        ("0.9.9", "1.0.0"),
    ],
)
def test_npm_precedence(lower: str, higher: str) -> None:
    assert compare(npm(lower), npm(higher)) < 0
    assert compare(npm(higher), npm(lower)) > 0


def test_npm_build_metadata_is_ignored_for_precedence() -> None:
    assert compare(npm("1.0.0+build.5"), npm("1.0.0")) == 0
    assert compare(npm("1.0.0+build.5"), npm("1.0.0+other")) == 0


def test_npm_release_precedence_ignores_build_against_prerelease() -> None:
    assert compare(npm("1.0.0-rc.1+x"), npm("1.0.0+y")) < 0


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.0.dev1", "1.0a1"),
        ("1.0a1", "1.0a2"),
        ("1.0a2", "1.0b1"),
        ("1.0b2", "1.0rc1"),
        ("1.0rc1", "1.0"),
        ("1.0", "1.0.post1"),
        ("1.0.post1", "1.0.post2"),
        ("1.0", "1.1"),
        ("1.9", "2!1.0"),
        ("1.0a1", "1.0a1.post1"),
        ("1.0a1.dev1", "1.0a1"),
        ("1.0", "1.0+local"),
        ("1.0+local.1", "1.0+local.2"),
    ],
)
def test_pypi_precedence(lower: str, higher: str) -> None:
    assert compare(pypi(lower), pypi(higher)) < 0
    assert compare(pypi(higher), pypi(lower)) > 0


def test_pypi_zero_padding_is_precedence_equal() -> None:
    assert compare(pypi("1.0.0"), pypi("1.0")) == 0
    assert compare(pypi("1.02"), pypi("1.2")) == 0


def test_pypi_spelling_variants_are_precedence_equal() -> None:
    assert compare(pypi("1.0-alpha1"), pypi("1.0a1")) == 0
    assert compare(pypi("1.0_rc1"), pypi("1.0rc1")) == 0


def test_compare_reflexive() -> None:
    assert compare(npm("1.2.3"), npm("1.2.3")) == 0
    assert compare(pypi("1.0"), pypi("1.0")) == 0


def test_cross_ecosystem_compare_is_unsupported() -> None:
    with pytest.raises(UnsupportedVersion):
        compare(npm("1.0.0"), pypi("1.0"))
