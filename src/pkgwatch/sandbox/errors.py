"""Sandbox rejection types and archive-error mapping."""

from __future__ import annotations

from typing import NoReturn

from pkgwatch.models import RejectionCode, SandboxRejection


class ArchiveRejected(Exception):
    """Raised when an archive violates a limit or a structural safety rule."""

    def __init__(self, rejection: SandboxRejection) -> None:
        super().__init__(f"{rejection.reason_code.value}: {rejection.detail}")
        self.rejection = rejection


def reject(
    code: RejectionCode,
    detail: str,
    *,
    offending_path: str | None = None,
    limit_name: str | None = None,
    limit_value: float | None = None,
    observed_value: float | None = None,
) -> NoReturn:
    raise ArchiveRejected(
        SandboxRejection(
            reason_code=code,
            detail=detail,
            offending_path=offending_path,
            limit_name=limit_name,
            limit_value=limit_value,
            observed_value=observed_value,
        )
    )


def reject_archive_error(exc: BaseException) -> NoReturn:
    """Map a container-format exception to a stable rejection code."""
    text = str(exc).lower()
    truncated_markers = (
        "truncated",
        "unexpected end",
        "end of",
        "end-of-stream",
        "crc",
        "incomplete",
        "not a gzip",
        "compressed data ended",
        "empty file",
    )
    if isinstance(exc, EOFError) or any(marker in text for marker in truncated_markers):
        reject(RejectionCode.ARCHIVE_TRUNCATED, f"archive could not be read completely: {exc}")
    reject(RejectionCode.ARCHIVE_FORMAT_UNSUPPORTED, f"archive could not be parsed: {exc}")
