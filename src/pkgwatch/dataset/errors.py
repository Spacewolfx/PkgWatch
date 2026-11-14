"""Dataset rejection types. A stable code plus a detail we computed, never package text."""

from __future__ import annotations


class DatasetError(Exception):
    def __init__(self, code: str, *, detail: str = "") -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail
