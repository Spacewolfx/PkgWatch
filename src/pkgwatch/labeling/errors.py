"""Label rejection types. A stable code plus a row number, never file content."""

from __future__ import annotations


class LabelError(Exception):
    """Carries a stable code only; ``row`` is a 1-based CSV record number, not cell text.

    A record is not a physical line: a quoted note with embedded newlines spans lines.
    """

    def __init__(self, code: str, *, row: int | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.row = row
