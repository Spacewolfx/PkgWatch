"""Root metadata resolution and parsing for PyPI (SPEC §4.5.2).

The metadata document is ``PKG-INFO`` for an sdist and ``METADATA`` inside a
``.dist-info`` directory for a wheel; both are the package's own shipped text, never
registry data. ``root_metadata_path`` resolves the shipped file deterministically and
``parse_metadata`` extracts the declared dependencies, never raising on hostile input.
"""

from __future__ import annotations

from pathlib import Path

from pkgwatch.diff.pypi_metadata import metadata_text, parse_metadata, root_metadata_path
from pkgwatch.models import Ecosystem
from tests.support.context import ctx_from_files
from tests.support.pypi_registry import metadata_text as build_metadata


def _ctx(
    tmp_path: Path,
    old_files: dict[str, bytes],
    new_files: dict[str, bytes],
    **kwargs: object,
) -> object:
    return ctx_from_files(
        tmp_path,
        old_files,
        new_files,
        package_name="demo",
        ecosystem=Ecosystem.PYPI,
        old_version="1.0.0",
        new_version="1.1.0",
        **kwargs,  # type: ignore[arg-type]
    )


def test_sdist_side_resolves_pkg_info_after_re_rooting(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path,
        {"demo-1.0.0/PKG-INFO": build_metadata("demo", "1.0.0").encode()},
        {"demo-1.1.0/PKG-INFO": build_metadata("demo", "1.1.0").encode()},
    )

    # The {name}-{version}/ root is stripped before diffing, so both sides' metadata
    # document is the same depth-0 path.
    assert root_metadata_path(ctx, "old") == "PKG-INFO"
    assert root_metadata_path(ctx, "new") == "PKG-INFO"
    assert "Version: 1.0.0" in (metadata_text(ctx, "old") or "")
    assert "Version: 1.1.0" in (metadata_text(ctx, "new") or "")


def test_wheel_side_resolves_dist_info_metadata(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path,
        {
            "demo/__init__.py": b"",
            "demo-1.0.0.dist-info/METADATA": build_metadata("demo", "1.0.0").encode(),
        },
        {
            "demo/__init__.py": b"",
            "demo-1.1.0.dist-info/METADATA": build_metadata("demo", "1.1.0").encode(),
        },
    )

    assert root_metadata_path(ctx, "old") == "demo-1.0.0.dist-info/METADATA"
    assert root_metadata_path(ctx, "new") == "demo-1.1.0.dist-info/METADATA"


def test_pkg_info_wins_over_metadata_when_both_present(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path,
        {"demo-1.0.0/PKG-INFO": build_metadata("demo", "1.0.0").encode()},
        {
            "demo-1.1.0.dist-info/METADATA": build_metadata("demo", "1.1.0").encode(),
            "demo-1.1.0/PKG-INFO": build_metadata("demo", "1.1.0").encode(),
        },
    )

    assert root_metadata_path(ctx, "new") == "demo-1.1.0/PKG-INFO"


def test_absent_metadata_resolves_to_none_and_never_raises(tmp_path: Path) -> None:
    ctx = _ctx(
        tmp_path,
        {"demo/__init__.py": b"VERSION = '1.0.0'\n"},
        {"demo/__init__.py": b"VERSION = '1.1.0'\n"},
    )

    assert root_metadata_path(ctx, "old") is None
    assert root_metadata_path(ctx, "new") is None
    assert metadata_text(ctx, "old") is None
    assert metadata_text(ctx, "new") is None


def test_parse_metadata_extracts_name_version_and_dependencies() -> None:
    text = build_metadata("demo", "1.1.0", requires=("requests>=2.0", "colorama"))

    parsed = parse_metadata(text)

    assert parsed.name == "demo"
    assert parsed.version == "1.1.0"
    assert parsed.dependencies == {"requests": ">=2.0", "colorama": ""}


def test_parse_metadata_name_extraction_ignores_extras_and_markers() -> None:
    text = (
        "Metadata-Version: 2.1\n"
        "Name: demo\n"
        "Version: 1.1.0\n"
        'Requires-Dist: requests[security]>=2.0; python_version>"3.8"\n'
        "Requires-Dist: Foo_Bar\n"
    )

    parsed = parse_metadata(text)

    assert parsed.dependencies["requests"] == ">=2.0"
    assert parsed.dependencies["foo-bar"] == ""


def test_parse_metadata_is_defensive_about_hostile_input() -> None:
    assert parse_metadata("").name == ""
    assert parse_metadata("not a header\n").dependencies == {}
    # A malformed Requires-Dist line is skipped, never raised on.
    parsed = parse_metadata("Requires-Dist: \nRequires-Dist: ok>=1\n")
    assert parsed.dependencies == {"ok": ">=1"}
