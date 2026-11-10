"""The ``rules`` catalog command: ecosystem filtering and per-rule ecosystem metadata."""

from __future__ import annotations

import json

import pytest

from pkgwatch import cli


def _run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str, str]:
    code = cli.main(["rules", *args])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_json_catalog_lists_every_rule_with_its_ecosystems(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code, out, err = _run(capsys, "--json")
    payload = json.loads(out)
    assert code == 0
    assert err == ""
    assert payload["total_rules"] == 18
    for entry in payload["rules"]:
        assert entry["ecosystems"]
        assert set(entry["ecosystems"]) <= {"npm", "pypi"}


def test_ecosystem_filter_selects_only_pypi_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, "--json", "--ecosystem", "pypi")
    payload = json.loads(out)
    assert code == 0
    assert payload["total_rules"] == 6
    assert all(entry["rule_id"].startswith("PYPI_") for entry in payload["rules"])
    assert all("pypi" in entry["ecosystems"] for entry in payload["rules"])


def test_ecosystem_filter_selects_only_npm_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, "--json", "--ecosystem", "npm")
    payload = json.loads(out)
    assert code == 0
    assert payload["total_rules"] == 12
    assert all(not entry["rule_id"].startswith("PYPI_") for entry in payload["rules"])
    assert all("npm" in entry["ecosystems"] for entry in payload["rules"])


def test_text_mode_shows_ecosystems(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, "--ecosystem", "pypi")
    assert code == 0
    assert "total rules: 6" in out
    assert "ecosystems: pypi" in out
    assert "PYPI_INSTALL_HOOK_ADDED" in out


def test_markdown_mode_has_an_ecosystems_column(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _run(capsys, "--markdown", "--ecosystem", "npm")
    assert code == 0
    assert "| Ecosystems |" in out
    assert "`npm`" in out


def test_unknown_ecosystem_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["rules", "--ecosystem", "cargo"])
    assert exc.value.code == 2
