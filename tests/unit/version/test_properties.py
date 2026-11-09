"""Hypothesis property tests for the version parser (SPEC §6.4).

Versions are generated from components in each ecosystem's own grammar, so every
sample is a valid version by construction; the properties under test are the order
laws, canonical round-trip and sort determinism — not acceptance fuzzing.
"""

from __future__ import annotations

import itertools

from hypothesis import given, settings
from hypothesis import strategies as st

from pkgwatch.models import Ecosystem
from pkgwatch.version import compare, parse

_PRE_WORDS = ("alpha", "beta", "rc", "a", "x9")


@st.composite
def npm_versions(draw: st.DrawFn) -> str:
    core = ".".join(str(draw(st.integers(min_value=0, max_value=99))) for _ in range(3))
    if draw(st.booleans()):
        count = draw(st.integers(min_value=1, max_value=3))
        parts = [
            str(draw(st.integers(min_value=0, max_value=999)))
            if draw(st.booleans())
            else draw(st.sampled_from(_PRE_WORDS))
            for _ in range(count)
        ]
        core += "-" + ".".join(parts)
        if draw(st.booleans()):
            core += "+build." + str(draw(st.integers(min_value=0, max_value=99)))
    return core


@st.composite
def pypi_versions(draw: st.DrawFn) -> str:
    text = ""
    if draw(st.booleans()):
        text += f"{draw(st.integers(min_value=1, max_value=3))}!"
    segments = draw(st.integers(min_value=1, max_value=4))
    text += ".".join(str(draw(st.integers(min_value=0, max_value=30))) for _ in range(segments))
    has_dev = False
    if draw(st.booleans()):
        letter = draw(st.sampled_from(("a", "b", "rc")))
        number = draw(st.integers(min_value=0, max_value=9))
        text += f"{letter}{number}"
        if draw(st.booleans()):
            text += f".dev{draw(st.integers(min_value=0, max_value=9))}"
            has_dev = True
    elif draw(st.booleans()):
        text += f".dev{draw(st.integers(min_value=0, max_value=9))}"
        has_dev = True
    # PEP 440 orders .post before .dev: "X.devN.postM" is not a version.
    if not has_dev and draw(st.booleans()):
        text += f".post{draw(st.integers(min_value=0, max_value=9))}"
        if draw(st.booleans()):
            text += f".dev{draw(st.integers(min_value=0, max_value=9))}"
    if draw(st.booleans()):
        text += f"+local.{draw(st.integers(min_value=0, max_value=9))}"
    return text


SAMPLES = {"npm": npm_versions(), "pypi": pypi_versions()}


def _parse(ecosystem: str, text: str):  # type: ignore[no-untyped-def]
    return parse(Ecosystem(ecosystem), text)


@settings(max_examples=200)
@given(ecosystem=st.sampled_from(("npm", "pypi")), text=st.data())
def test_reflexive(ecosystem: str, text: st.DataObject) -> None:
    version = _parse(ecosystem, text.draw(SAMPLES[ecosystem]))
    assert compare(version, version) == 0


@settings(max_examples=200)
@given(ecosystem=st.sampled_from(("npm", "pypi")), data=st.data())
def test_antisymmetric(ecosystem: str, data: st.DataObject) -> None:
    a = _parse(ecosystem, data.draw(SAMPLES[ecosystem]))
    b = _parse(ecosystem, data.draw(SAMPLES[ecosystem]))
    assert compare(a, b) == -compare(b, a)


@settings(max_examples=200)
@given(ecosystem=st.sampled_from(("npm", "pypi")), data=st.data())
def test_transitive(ecosystem: str, data: st.DataObject) -> None:
    a = _parse(ecosystem, data.draw(SAMPLES[ecosystem]))
    b = _parse(ecosystem, data.draw(SAMPLES[ecosystem]))
    c = _parse(ecosystem, data.draw(SAMPLES[ecosystem]))
    if compare(a, b) <= 0 and compare(b, c) <= 0:
        assert compare(a, c) <= 0
    if compare(a, b) >= 0 and compare(b, c) >= 0:
        assert compare(a, c) >= 0


@settings(max_examples=100)
@given(ecosystem=st.sampled_from(("npm", "pypi")), texts=st.data())
def test_round_trip_canonical(ecosystem: str, texts: st.DataObject) -> None:
    version = _parse(ecosystem, texts.draw(SAMPLES[ecosystem]))
    again = parse(version.ecosystem, version.canonical)
    assert again.canonical == version.canonical
    assert compare(again, version) == 0


@settings(max_examples=50)
@given(ecosystem=st.sampled_from(("npm", "pypi")), data=st.data())
def test_sort_is_deterministic_and_stable(ecosystem: str, data: st.DataObject) -> None:
    texts = data.draw(st.lists(SAMPLES[ecosystem], min_size=2, max_size=12))
    versions = [_parse(ecosystem, item) for item in texts]
    once = sorted(versions, key=lambda item: (item.key, item.text))
    twice = sorted(once, key=lambda item: (item.key, item.text))
    assert once == twice
    for lower, higher in itertools.pairwise(once):
        assert compare(lower, higher) <= 0
