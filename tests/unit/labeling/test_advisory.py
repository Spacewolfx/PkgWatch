"""Advisory labels come from operator-supplied local OSV JSON. No network, ever."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgwatch.labeling.advisory import load_advisories, normalize_pypi_name
from pkgwatch.labeling.errors import LabelError
from pkgwatch.models import Ecosystem, Label

IDENTITY = ("npm", "demo-pkg", "1.0.0", "1.1.0")


def _osv(*, versions: list[str] | None = None, events: list[dict[str, str]] | None = None) -> dict:
    affected: dict = {"package": {"ecosystem": "npm", "name": "demo-pkg"}}
    if versions is not None:
        affected["versions"] = versions
    if events is not None:
        affected["ranges"] = [{"type": "SEMVER", "events": events}]
    return {"id": "MAL-2026-1", "affected": [affected]}


def _write(tmp_path: Path, document: dict, name: str = "MAL-2026-1.json") -> Path:
    directory = tmp_path / "advisories"
    directory.mkdir(exist_ok=True)
    (directory / name).write_text(json.dumps(document), encoding="utf-8")
    return directory


def test_a_listed_version_is_malicious(tmp_path: Path) -> None:
    directory = _write(tmp_path, _osv(versions=["1.1.0"]))
    claims = load_advisories(directory, [IDENTITY])
    assert len(claims) == 1
    assert claims[0].label is Label.MALICIOUS
    assert claims[0].confidence == 0.9
    assert claims[0].provenance.startswith("osv:MAL-2026-1:")
    assert len(claims[0].provenance.rsplit(":", 1)[1]) == 12


def test_a_version_inside_an_introduced_interval_is_malicious(tmp_path: Path) -> None:
    directory = _write(tmp_path, _osv(events=[{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]))
    assert load_advisories(directory, [IDENTITY])[0].label is Label.MALICIOUS


def test_the_osv_origin_sentinel_opens_an_interval(tmp_path: Path) -> None:
    # SPEC §5.2: `introduced: "0"` is negative infinity, not an unparseable version.
    # It is the dominant shape in OpenSSF malicious-packages; npm parse("0") raises.
    directory = _write(tmp_path, _osv(events=[{"introduced": "0"}, {"fixed": "1.2.0"}]))
    assert load_advisories(directory, [IDENTITY])[0].label is Label.MALICIOUS


def test_the_osv_origin_sentinel_with_no_upper_bound_is_malicious(tmp_path: Path) -> None:
    directory = _write(tmp_path, _osv(events=[{"introduced": "0"}]))
    assert load_advisories(directory, [IDENTITY])[0].label is Label.MALICIOUS


def test_an_unparseable_fixed_bound_does_not_claim_coverage(tmp_path: Path) -> None:
    # SPEC §5.2: fail closed. An interval whose upper end is unknown proves nothing.
    directory = _write(tmp_path, _osv(events=[{"introduced": "1.0.0"}, {"fixed": "not-a-version"}]))
    assert load_advisories(directory, [IDENTITY])[0].label is Label.UNKNOWN


def test_a_fixed_bound_equal_to_the_record_version_is_not_covered(tmp_path: Path) -> None:
    directory = _write(tmp_path, _osv(events=[{"introduced": "1.0.0"}, {"fixed": "1.1.0"}]))
    assert load_advisories(directory, [IDENTITY])[0].label is Label.UNKNOWN


def test_a_version_outside_every_interval_is_an_explicit_unknown(tmp_path: Path) -> None:
    directory = _write(tmp_path, _osv(versions=["0.9.0"]))
    claims = load_advisories(directory, [IDENTITY])
    assert claims[0].label is Label.UNKNOWN
    assert claims[0].confidence == 0.9


def test_a_different_package_is_not_a_claim(tmp_path: Path) -> None:
    document = _osv(versions=["1.1.0"])
    document["affected"][0]["package"]["name"] = "other-pkg"
    assert load_advisories(_write(tmp_path, document), [IDENTITY]) == ()


def test_pypi_names_are_normalised_on_both_sides() -> None:
    assert normalize_pypi_name("Foo_Bar.Baz") == "foo-bar-baz"


def test_every_name_matching_advisory_is_returned_in_sorted_order(tmp_path: Path) -> None:
    # SPEC §5.2: the losers must survive so Task 9 can record `advisory_duplicate`.
    directory = _write(tmp_path, _osv(versions=["1.1.0"]), name="b.json")
    _write(tmp_path, _osv(versions=["0.9.0"]), name="a.json")
    claims = load_advisories(directory, [IDENTITY])
    assert [claim.filename for claim in claims] == ["a.json", "b.json"]
    assert [claim.label for claim in claims] == [Label.UNKNOWN, Label.MALICIOUS]


def test_malformed_json_rejects_the_file(tmp_path: Path) -> None:
    directory = tmp_path / "advisories"
    directory.mkdir()
    (directory / "bad.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(LabelError) as excinfo:
        load_advisories(directory, [IDENTITY])
    assert excinfo.value.code == "ADVISORY_JSON_INVALID"


def test_a_missing_directory_means_no_claims(tmp_path: Path) -> None:
    assert load_advisories(tmp_path / "absent", [IDENTITY]) == ()


def test_last_affected_is_inclusive(tmp_path: Path) -> None:
    directory = _write(tmp_path, _osv(events=[{"introduced": "1.0.0"}, {"last_affected": "1.1.0"}]))
    assert load_advisories(directory, [IDENTITY])[0].label is Label.MALICIOUS


def test_a_second_introduced_fixed_pair_in_one_events_list_still_matches(tmp_path: Path) -> None:
    directory = _write(
        tmp_path,
        _osv(
            events=[
                {"introduced": "0.1.0"},
                {"fixed": "0.5.0"},
                {"introduced": "1.0.0"},
                {"fixed": "1.2.0"},
            ]
        ),
    )
    assert load_advisories(directory, [IDENTITY])[0].label is Label.MALICIOUS


def test_a_fail_closed_reset_does_not_lose_a_later_interval(tmp_path: Path) -> None:
    directory = _write(
        tmp_path,
        _osv(
            events=[
                {"introduced": "1.0.0"},
                {"fixed": "not-a-version"},
                {"introduced": "1.0.0"},
                {"fixed": "1.2.0"},
            ]
        ),
    )
    assert load_advisories(directory, [IDENTITY])[0].label is Label.MALICIOUS


def test_pypi_end_to_end_normalises_the_advisory_name(tmp_path: Path) -> None:
    document = {
        "id": "MAL-2026-2",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "Demo_Pkg"}, "versions": ["1.1.0"]}],
    }
    directory = _write(tmp_path, document, name="MAL-2026-2.json")
    claims = load_advisories(directory, [("pypi", "demo-pkg", "1.0.0", "1.1.0")])
    assert len(claims) == 1
    assert claims[0].label is Label.MALICIOUS
    assert claims[0].ecosystem is Ecosystem.PYPI


def test_an_over_long_version_string_is_skipped_not_a_crash(tmp_path: Path) -> None:
    # Beyond Python's 4300-digit int limit: the version is skipped, never coerced,
    # and the claim is an explicit UNKNOWN — no raw ValueError may escape.
    directory = _write(tmp_path, _osv(versions=["9" * 5000 + ".0.0"]))
    claims = load_advisories(directory, [IDENTITY])
    assert len(claims) == 1
    assert claims[0].label is Label.UNKNOWN


def test_a_deeply_nested_json_document_rejects_the_file(tmp_path: Path) -> None:
    directory = tmp_path / "advisories"
    directory.mkdir()
    (directory / "deep.json").write_text("[" * 10000 + "]" * 10000, encoding="utf-8")
    with pytest.raises(LabelError) as excinfo:
        load_advisories(directory, [IDENTITY])
    assert excinfo.value.code == "ADVISORY_JSON_INVALID"
