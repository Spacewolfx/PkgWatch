"""Ecosystem version parsing and precedence (SPEC §6.4).

One total order per ecosystem over exact version strings: npm/crates-style semver
(``MAJOR.MINOR.PATCH[-prerelease][+build]``) and PyPI's PEP 440. Build metadata is
accepted and ignored for npm precedence — a partial order, so two versions can compare
equal without being the same text. Own code on purpose: SPEC §6.4 forbids a third-party
version dependency. Garbage and unknown ecosystems raise :class:`UnsupportedVersion`;
callers map that to their own stable error codes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pkgwatch.models import Ecosystem

# Same acceptance grammar as ``fetch.npm`` has always used: exact versions only, no
# ranges, tags or wildcards. Leading-zero prerelease identifiers stay accepted so the
# delegation from ``validate_version`` does not narrow what npm compare accepts.
_NPM_RE = re.compile(
    r"(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)\.(?P<patch>0|[1-9][0-9]*)"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?"
    r"(?:\+(?P<build>[0-9A-Za-z.-]+))?"
)

# PEP 440's own reference grammar: epoch, release segments, pre/post/dev spellings with
# [-_.] separators, implicit post (``1.0-1``) and a local segment.
_PEP440_RE = re.compile(
    r"""
    v?
    (?:(?P<epoch>[0-9]+)!)?
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-.]?(?P<pre_n>[0-9]+)?)?
    (?:
        (?:-(?P<post_n1>[0-9]+))
        |
        (?:[-_.]?(?P<post_l>post|rev|r)[-.]?(?P<post_n2>[0-9]+)?)
    )?
    (?P<dev>[-_.]?dev[-_.]?(?P<dev_n>[0-9]+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PRE_LETTER = {
    "alpha": "a",
    "a": "a",
    "beta": "b",
    "b": "b",
    "preview": "rc",
    "pre": "rc",
    "c": "rc",
    "rc": "rc",
}
_PRE_ORDER = {"a": 0, "b": 1, "rc": 2}


class UnsupportedVersion(Exception):
    """Version text that has no precedence in its ecosystem, or an ecosystem mismatch."""


class _Inf:
    """Sorts after everything; used for PEP 440's 'absent component' sentinels."""

    def __lt__(self, other: object) -> bool:
        return False

    def __le__(self, other: object) -> bool:
        return isinstance(other, _Inf)

    def __gt__(self, other: object) -> bool:
        return not isinstance(other, _Inf)

    def __ge__(self, other: object) -> bool:
        return True

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _Inf)

    def __ne__(self, other: object) -> bool:
        return not isinstance(other, _Inf)

    def __hash__(self) -> int:
        return hash(_Inf)


class _NegInf:
    """Sorts before everything."""

    def __lt__(self, other: object) -> bool:
        return not isinstance(other, _NegInf)

    def __le__(self, other: object) -> bool:
        return True

    def __gt__(self, other: object) -> bool:
        return False

    def __ge__(self, other: object) -> bool:
        return isinstance(other, _NegInf)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _NegInf)

    def __ne__(self, other: object) -> bool:
        return not isinstance(other, _NegInf)

    def __hash__(self) -> int:
        return hash(_NegInf)


_INF = _Inf()
_NEG_INF = _NegInf()


@dataclass(frozen=True)
class ParsedVersion:
    """One exact version. ``key`` is the precedence sort key within its ecosystem."""

    ecosystem: Ecosystem
    text: str
    canonical: str
    key: tuple[Any, ...]


def parse(ecosystem: Ecosystem, text: str) -> ParsedVersion:
    """Parse an exact version string into a precedence-comparable form.

    npm keeps its text verbatim as the canonical form; PEP 440 canonicalises
    (``1.0-ALPHA1`` → ``1.0a1``, zeros stripped, ``v`` prefix dropped). Raises
    :class:`UnsupportedVersion` on anything the ecosystem's grammar does not accept.
    """
    if ecosystem is Ecosystem.NPM:
        return _parse_npm(text)
    if ecosystem is Ecosystem.PYPI:
        return _parse_pypi(text)
    raise UnsupportedVersion(f"unsupported ecosystem: {ecosystem.value}")


def compare(a: ParsedVersion, b: ParsedVersion) -> int:
    """Precedence comparison: negative, zero or positive, like a cmp function.

    Zero means precedence-equal, not textually equal (``1.0.0+b1`` vs ``1.0.0+b2``,
    ``1.0`` vs ``1.0.0``). Cross-ecosystem comparison has no defined order.
    """
    if a.ecosystem is not b.ecosystem:
        raise UnsupportedVersion("cannot compare versions across ecosystems")
    if a.key < b.key:
        return -1
    if a.key > b.key:
        return 1
    return 0


def _parse_npm(text: str) -> ParsedVersion:
    match = _NPM_RE.fullmatch(text)
    if match is None:
        raise UnsupportedVersion("not an exact npm version")
    pre = match.group("pre")
    key: tuple[Any, ...] = (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        _INF if pre is None else _npm_pre_key(pre),
    )
    return ParsedVersion(ecosystem=Ecosystem.NPM, text=text, canonical=text, key=key)


def _npm_pre_key(pre: str) -> tuple[Any, ...]:
    """Semver §11: numeric identifiers sort before alphanumeric ones, numerically."""
    identifiers: list[Any] = []
    for identifier in pre.split("."):
        if identifier.isdigit():
            identifiers.append((0, int(identifier), ""))
        else:
            identifiers.append((1, 0, identifier))
    return tuple(identifiers)


def _parse_pypi(text: str) -> ParsedVersion:
    match = _PEP440_RE.fullmatch(text)
    if match is None:
        raise UnsupportedVersion("not a PEP 440 version")

    epoch = int(match.group("epoch") or 0)
    release = tuple(int(segment) for segment in match.group("release").split("."))
    has_dev = match.group("dev") is not None
    has_post = match.group("post_n1") is not None or match.group("post_l") is not None

    pre_letter = match.group("pre_l")
    pre: Any
    pre_key: tuple[int, int] | None
    if pre_letter is None:
        # PEP 440: a dev release of a final version sorts before every prerelease;
        # otherwise an absent pre means "after all prereleases" (final/post).
        pre = _NEG_INF if has_dev and not has_post else _INF
        pre_key = None
    else:
        letter = _PRE_LETTER[pre_letter.lower()]
        pre_key = (_PRE_ORDER[letter], int(match.group("pre_n") or 0))
        pre = pre_key

    post: Any
    if match.group("post_n1") is not None:
        post = int(match.group("post_n1"))
    elif match.group("post_l") is not None:
        post = int(match.group("post_n2") or 0)
    else:
        post = _NEG_INF

    dev: Any = int(match.group("dev_n") or 0) if has_dev else _INF

    local_raw = match.group("local")
    local: Any
    if local_raw is None:
        local = _NEG_INF
    else:
        local = tuple(
            (int(segment), "") if segment.isdigit() else (_NEG_INF, segment.lower())
            for segment in re.split(r"[-_.]", local_raw)
        )

    # Precedence key: trailing zero release segments are insignificant (1.0 == 1.0.0).
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()
    key: tuple[Any, ...] = (epoch, tuple(trimmed), pre, post, dev, local)

    canonical = _pypi_canonical(epoch, release, pre_key, post, dev, local_raw)
    return ParsedVersion(ecosystem=Ecosystem.PYPI, text=text, canonical=canonical, key=key)


def _pypi_canonical(
    epoch: int,
    release: tuple[int, ...],
    pre_key: tuple[int, int] | None,
    post: Any,
    dev: Any,
    local_raw: str | None,
) -> str:
    text = f"{epoch}!" if epoch else ""
    text += ".".join(str(segment) for segment in release)
    if pre_key is not None:
        letter = next(name for name, order in _PRE_ORDER.items() if order == pre_key[0])
        text += f"{letter}{pre_key[1]}"
    if not isinstance(post, _NegInf):
        text += f".post{post}"
    if not isinstance(dev, _Inf):
        text += f".dev{dev}"
    if local_raw is not None:
        text += "+" + re.sub(r"[-_.]", ".", local_raw).lower()
    return text
