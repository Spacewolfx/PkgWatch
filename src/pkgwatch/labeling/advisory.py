"""Advisory labels: operator-supplied local OSV JSON (SPEC §7.4). No network, ever.

Selection is by ecosystem + name only; the version decides ``MALICIOUS`` vs ``UNKNOWN``,
never whether a claim exists. Every name-matching advisory is returned so the policy can
record the losers as ``advisory_duplicate`` conflicts (SPEC §5.2).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pkgwatch.labeling.errors import LabelError
from pkgwatch.models import Ecosystem, Label
from pkgwatch.version import ParsedVersion, UnsupportedVersion, compare, parse

_OSV_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
_CONFIDENCE = 0.9


@dataclass(frozen=True)
class AdvisoryLabel:
    ecosystem: Ecosystem
    package_name: str
    old_version: str
    new_version: str
    label: Label
    confidence: float
    provenance: str
    advisory_id: str
    filename: str

    @property
    def identity(self) -> tuple[str, str, str, str]:
        return (self.ecosystem.value, self.package_name, self.old_version, self.new_version)


def normalize_pypi_name(name: str) -> str:
    """PEP 503: lowercase, with runs of ``-_.`` collapsed to a single ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def load_advisories(
    directory: Path, identities: Sequence[tuple[str, str, str, str]]
) -> tuple[AdvisoryLabel, ...]:
    """Every name-matching advisory claim per identity, in sorted ``(filename, id)`` order.

    Identities stay in the order requested. A malformed file rejects the whole load; an
    advisory that simply does not mention the package is never an error.
    """
    if not directory.is_dir():
        return ()
    documents: list[tuple[Path, dict[str, Any], str]] = []
    for path in sorted(directory.glob("*.json")):
        document, digest = _read(path)
        documents.append((path, document, digest))
    claims: list[AdvisoryLabel] = []
    for ecosystem, package_name, old_version, new_version in identities:
        matched: list[AdvisoryLabel] = []
        for path, document, digest in documents:
            entries = [
                entry
                for entry in document["affected"]
                if isinstance(entry, Mapping) and _name_matches(entry, ecosystem, package_name)
            ]
            if not entries:
                continue
            covered = any(_covers(entry, ecosystem, package_name, new_version) for entry in entries)
            matched.append(
                AdvisoryLabel(
                    ecosystem=Ecosystem(ecosystem),
                    package_name=package_name,
                    old_version=old_version,
                    new_version=new_version,
                    label=Label.MALICIOUS if covered else Label.UNKNOWN,
                    confidence=_CONFIDENCE,
                    provenance=f"osv:{document['id']}:{digest}",
                    advisory_id=document["id"],
                    filename=path.name,
                )
            )
        claims.extend(sorted(matched, key=lambda claim: (claim.filename, claim.advisory_id)))
    return tuple(claims)


def _read(path: Path) -> tuple[dict[str, Any], str]:
    """Parse one OSV file and digest the very same bytes: one read, no parse-vs-hash gap."""
    try:
        raw = path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        # ValueError covers json.JSONDecodeError and the >4300-digit int() limit that a
        # hostile document can trip while decoding an integer literal.
        raise LabelError("ADVISORY_JSON_INVALID") from None
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("id"), str)
        or not document["id"]
        or not isinstance(document.get("affected"), list)
    ):
        raise LabelError("ADVISORY_JSON_INVALID")
    return document, hashlib.sha256(raw).hexdigest()[:12]


def _name_matches(entry: Mapping[str, Any], ecosystem: str, package_name: str) -> bool:
    osv_ecosystem = _OSV_ECOSYSTEMS.get(ecosystem)
    if osv_ecosystem is None:
        return False
    package = entry.get("package")
    if not isinstance(package, Mapping) or package.get("ecosystem") != osv_ecosystem:
        return False
    name = package.get("name")
    if not isinstance(name, str):
        return False
    if ecosystem == "pypi":
        return normalize_pypi_name(name) == normalize_pypi_name(package_name)
    return name == package_name


def _covers(entry: Mapping[str, Any], ecosystem: str, package_name: str, version: str) -> bool:
    """Name match plus version membership in ``versions[]`` or a ``ranges[]`` interval."""
    if not _name_matches(entry, ecosystem, package_name):
        return False
    eco = Ecosystem(ecosystem)
    target = _parse_or_none(eco, version)
    if target is None:
        return False
    listed = entry.get("versions")
    if isinstance(listed, list):
        for candidate in listed:
            parsed = _parse_or_none(eco, candidate)
            if parsed is not None and parsed.canonical == target.canonical:
                return True
    ranges = entry.get("ranges")
    if isinstance(ranges, list):
        for interval in ranges:
            if isinstance(interval, Mapping) and _events_cover(interval.get("events"), eco, target):
                return True
    return False


def _events_cover(events: Any, ecosystem: Ecosystem, version: ParsedVersion) -> bool:
    """``introduced`` opens an interval; ``fixed``/``last_affected`` close it.

    ``fixed`` is exclusive (the fix landed in that version), ``last_affected`` inclusive;
    an unclosed interval extends to infinity. Unparseable versions are skipped, never
    coerced, with two pinned semantics (SPEC §5.2): the literal ``"0"`` on ``introduced``
    is the OSV origin sentinel (negative infinity), tracked as ``from_origin`` instead of
    a parsed lower bound; an unparseable closing bound closes its interval without
    claiming coverage (fail closed), so a later ``introduced`` can still open a new one.
    """
    if not isinstance(events, list):
        return False
    introduced: ParsedVersion | None = None
    from_origin = False
    for event in events:
        if not isinstance(event, Mapping):
            continue
        if "introduced" in event:
            if event["introduced"] == "0":
                introduced = None
                from_origin = True
            else:
                introduced = _parse_or_none(ecosystem, event["introduced"])
                from_origin = False
        elif "fixed" in event or "last_affected" in event:
            if introduced is None and not from_origin:
                continue
            closing = "fixed" if "fixed" in event else "last_affected"
            bound = _parse_or_none(ecosystem, event[closing])
            if bound is None:
                introduced = None
                from_origin = False
                continue
            upper = compare(version, bound)
            inside = upper < 0 if closing == "fixed" else upper <= 0
            if inside and (
                from_origin or (introduced is not None and compare(introduced, version) <= 0)
            ):
                return True
            introduced = None
            from_origin = False
    if from_origin:
        return True
    return introduced is not None and compare(introduced, version) <= 0


def _parse_or_none(ecosystem: Ecosystem, text: Any) -> ParsedVersion | None:
    if not isinstance(text, str):
        return None
    try:
        return parse(ecosystem, text)
    except UnsupportedVersion:
        return None
