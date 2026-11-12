"""``python -m pkgwatch`` must run the CLI: the GitHub Action invokes it this way.

Executed in-process with runpy (never a subprocess), with sys.argv patched so the
module's ``__main__`` guard calls ``cli.main`` and exits with its return code.
"""

from __future__ import annotations

import importlib.util
import runpy
import sys

import pytest

from pkgwatch import __version__


def test_python_m_pkgwatch_runs_the_cli_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert importlib.util.find_spec("pkgwatch.__main__") is not None, (
        "python -m pkgwatch needs src/pkgwatch/__main__.py"
    )
    monkeypatch.setattr(sys, "argv", ["pkgwatch", "version"])

    with pytest.raises(SystemExit) as caught:
        runpy.run_module("pkgwatch", run_name="__main__")

    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == __version__
