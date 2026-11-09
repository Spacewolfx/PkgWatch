"""The ``compare`` command against an injected offline PyPI registry.

Every artifact here is a synthetic sdist or wheel built from caller-supplied file maps
and served by ``tests.support.pypi_registry``: no live registry, no sockets, and no
package content is ever run. These cover the ``pypi:`` route's transport, report shape
and stable error codes. Rule-firing assertions land with the PyPI rules in M4.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkgwatch import cli
from pkgwatch.cli import DISCLAIMER
from pkgwatch.config import Config
from tests.support.pypi_registry import FILES_HOST, PYPI_HOST, PyPIRegistry, pypi_pair_registry

OLD_VERSION = "1.0.0"
NEW_VERSION = "1.1.0"
ALLOWED_PREFIXES = (f"https://{PYPI_HOST}/", f"https://{FILES_HOST}/")


def _benign(tmp_path: Path, **kwargs: object) -> PyPIRegistry:
    return pypi_pair_registry(
        tmp_path,
        "demo-pkg",
        old_version=OLD_VERSION,
        new_version=NEW_VERSION,
        old_files={"demo/__init__.py": b"__version__ = '1.0.0'\n"},
        new_files={"demo/__init__.py": b"__version__ = '1.1.0'\n"},
        **kwargs,  # type: ignore[arg-type]
    )


def _run(
    capsys: pytest.CaptureFixture[str],
    registry: PyPIRegistry,
    *extra: str,
    config: Config | None = None,
    first: str | None = None,
    second: str | None = None,
) -> tuple[int, str, str]:
    code = cli.main(
        [
            "compare",
            first if first is not None else f"pypi:{registry.name}@{OLD_VERSION}",
            second if second is not None else f"pypi:{registry.name}@{NEW_VERSION}",
            *extra,
        ],
        client=registry,
        config=config or Config(),
    )
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_benign_sdist_pair_exits_zero_with_pypi_ecosystem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    code, out, err = _run(capsys, registry, "--json")
    payload = json.loads(out)

    assert code == 0
    assert err == ""
    assert payload["ecosystem"] == "pypi"
    assert payload["schema_version"] == 2
    assert payload["package"] == "demo-pkg"
    assert payload["old_version"] == OLD_VERSION
    assert payload["new_version"] == NEW_VERSION
    assert payload["findings"] == []
    assert payload["score"] == 0
    assert payload["digests"] == {"old": "sha256", "new": "sha256"}
    assert payload["measured"] is False
    assert payload["disclaimer"] == DISCLAIMER


def test_benign_sdist_pair_in_text_mode_shows_versions_score_and_disclaimer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    code, out, err = _run(capsys, registry)

    assert code == 0
    assert err == ""
    assert "package: demo-pkg" in out
    assert f"old version: {OLD_VERSION}" in out
    assert f"new version: {NEW_VERSION}" in out
    assert "findings: (none)" in out
    assert "score: 0" in out
    assert "digests: old=sha256, new=sha256" in out
    assert DISCLAIMER in out


def test_every_request_stays_on_the_pypi_host_allowlist(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    code, _, _ = _run(capsys, registry)

    assert code == 0
    assert len(registry.requests) == 3  # document + old artifact + new artifact
    assert all(url.startswith(ALLOWED_PREFIXES) for url in registry.requests)
    assert registry.requests[0] == f"https://{PYPI_HOST}/pypi/demo-pkg/json"


def test_wheel_only_pair_exits_zero(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = _benign(tmp_path, old_packagetype="bdist_wheel", new_packagetype="bdist_wheel")
    code, out, err = _run(capsys, registry, "--json")
    payload = json.loads(out)

    assert code == 0
    assert err == ""
    assert payload["ecosystem"] == "pypi"
    assert payload["score"] == 0


def test_mixed_sdist_to_wheel_pair_exits_zero(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path, new_packagetype="bdist_wheel")
    code, out, err = _run(capsys, registry, "--json")

    assert code == 0
    assert err == ""
    assert json.loads(out)["ecosystem"] == "pypi"


def test_blake2b_only_digest_is_reported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    registry.releases[NEW_VERSION][0]["digests"] = {
        "blake2b_256": registry.releases[NEW_VERSION][0]["digests"]["blake2b_256"]
    }
    registry.releases[OLD_VERSION][0]["digests"] = {
        "blake2b_256": registry.releases[OLD_VERSION][0]["digests"]["blake2b_256"]
    }

    code, out, err = _run(capsys, registry, "--json")

    assert code == 0
    assert err == ""
    assert json.loads(out)["digests"] == {"old": "blake2b_256", "new": "blake2b_256"}


def test_markdown_output_carries_the_pypi_ecosystem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    code, out, err = _run(capsys, registry, "--markdown")

    assert code == 0
    assert err == ""
    assert "pypi" in out
    assert "demo-pkg" in out
    assert DISCLAIMER in out


def test_sarif_output_carries_the_pypi_ecosystem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    code, out, err = _run(capsys, registry, "--sarif")
    document = json.loads(out)

    assert code == 0
    assert err == ""
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["properties"]["ecosystem"] == "pypi"
    assert run["properties"]["package"] == "demo-pkg"


def test_json_shape_is_stable_for_pypi(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = _benign(tmp_path)
    code, out, _ = _run(capsys, registry, "--json")
    payload = json.loads(out)

    assert code == 0
    assert set(payload) == {
        "schema_version",
        "ecosystem",
        "package",
        "old_version",
        "new_version",
        "files",
        "findings",
        "score",
        "boosts",
        "digests",
        "changed_files",
        "changed_files_omitted",
        "package_json_changes",
        "registry_metadata_changes",
        "explanations",
        "ignored_rules",
        "rule_set_version",
        "measured",
        "disclaimer",
    }
    assert set(payload["package_json_changes"]) == {"sections", "repository", "parse_problems"}


def test_digest_mismatch_exits_two_with_a_stable_code(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    registry.releases[NEW_VERSION][0]["digests"]["sha256"] = "0" * 64

    code, out, err = _run(capsys, registry, "--json")

    assert code == 2
    assert err.strip() == "DIGEST_MISMATCH"
    assert json.loads(out) == {"error": "DIGEST_MISMATCH", "measured": False}


def test_unknown_version_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    registry = _benign(tmp_path)
    del registry.releases[NEW_VERSION]

    code, _, err = _run(capsys, registry)

    assert code == 2
    assert err.strip() == "VERSION_NOT_FOUND"


def test_off_host_redirect_is_rejected_without_a_second_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)
    artifact_url = registry.releases[NEW_VERSION][0]["url"]
    registry.redirects[artifact_url] = "https://evil.example.org/demo.tar.gz"

    code, _, err = _run(capsys, registry)

    assert code == 2
    assert err.strip() == "REDIRECT_REJECTED"
    assert not any("evil.example" in url for url in registry.requests)


def test_mixing_ecosystems_is_a_package_mismatch_before_any_request(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)

    code, _, err = _run(
        capsys,
        registry,
        first="npm:demo-pkg@1.0.0",
        second=f"pypi:demo-pkg@{NEW_VERSION}",
    )

    assert code == 2
    assert err.strip() == "PACKAGE_MISMATCH"
    assert registry.requests == []


def test_pep503_spellings_of_one_name_are_the_same_package(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    registry = _benign(tmp_path)

    code, out, err = _run(
        capsys,
        registry,
        "--json",
        first=f"pypi:Demo_Pkg@{OLD_VERSION}",
        second=f"pypi:demo-pkg@{NEW_VERSION}",
    )

    assert code == 0
    assert err == ""
    assert json.loads(out)["ecosystem"] == "pypi"
    assert registry.requests[0] == f"https://{PYPI_HOST}/pypi/demo-pkg/json"


@pytest.mark.parametrize(
    ("first", "second", "code"),
    [
        ("pypi:demo-pkg", f"pypi:demo-pkg@{NEW_VERSION}", "INVALID_SPEC"),
        (f"pypi:demo-pkg@{OLD_VERSION}", "pypi:demo-pkg@1.0+", "INVALID_VERSION"),
        (f"pypi:demo-pkg@{OLD_VERSION}", "pypi:demo-pkg@^1.1.0", "INVALID_VERSION"),
        (f"pypi:-demo@{OLD_VERSION}", f"pypi:-demo@{NEW_VERSION}", "INVALID_PACKAGE_NAME"),
        (f"pypi:demo-pkg@{OLD_VERSION}", "pypi:other@1.1.0", "PACKAGE_MISMATCH"),
    ],
)
def test_invalid_pypi_specs_never_reach_the_network(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    first: str,
    second: str,
    code: str,
) -> None:
    registry = _benign(tmp_path)

    exit_code = cli.main(["compare", first, second], client=registry, config=Config())
    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.err.strip() == code
    assert registry.requests == []
