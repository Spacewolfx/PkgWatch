from __future__ import annotations

import argparse
from collections.abc import Callable

import pytest

from pkgwatch import cli


@pytest.mark.parametrize("validator", [cli._positive_int, cli._non_negative_int])
def test_integer_arguments_reject_a_trailing_newline(
    validator: Callable[[str], int],
) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        validator("5\n")
