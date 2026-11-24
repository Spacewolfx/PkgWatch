"""The console entry point turns SIGINT and a closed pipe into conventional exits.

Both handlers used to live in an ``if __name__ == "__main__"`` block inside ``cli.py``,
which neither the installed ``pkgwatch`` console script nor ``python -m pkgwatch``
executes. These tests pin them on ``main``, the function both entry points call.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from pkgwatch import cli


def test_keyboard_interrupt_exits_130(monkeypatch: pytest.MonkeyPatch) -> None:
    def _interrupt(*args: object, **kwargs: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_main", _interrupt)

    assert cli.main([]) == 130


def test_a_closed_pipe_exits_zero_and_redirects_stdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _broken(*args: object, **kwargs: object) -> int:
        raise BrokenPipeError

    class _Stdout:
        def fileno(self) -> int:
            return 1

    calls: list[tuple[int, int]] = []
    closed: list[int] = []

    def _dup2(source: int, target: int) -> None:
        calls.append((source, target))

    def _open(*args: Any, **kwargs: Any) -> int:
        return 7

    def _close(fd: int) -> None:
        # The descriptor 7 here is made up: closing it for real would hit pytest's capture
        # files, so the test records the call instead.
        closed.append(fd)

    monkeypatch.setattr(cli, "_main", _broken)
    monkeypatch.setattr(cli.os, "open", _open)
    monkeypatch.setattr(cli.os, "dup2", _dup2)
    monkeypatch.setattr(cli.os, "close", _close)
    monkeypatch.setattr(sys, "stdout", _Stdout())

    assert cli.main([]) == 0
    assert calls == [(7, 1)]
    assert closed == [7]


def test_a_closed_pipe_without_a_descriptor_still_exits_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # pytest capture and file-like replacements have no usable fileno; the redirect must
    # not turn a closed pipe into UnsupportedOperation escaping from the handler.
    def _broken(*args: object, **kwargs: object) -> int:
        raise BrokenPipeError

    class _Stdout:
        def fileno(self) -> int:
            raise OSError("no descriptor")

    monkeypatch.setattr(cli, "_main", _broken)
    monkeypatch.setattr(sys, "stdout", _Stdout())

    assert cli.main([]) == 0
