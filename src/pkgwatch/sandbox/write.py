"""Byte-accounted, hashing file copy shared by the tar and zip materialisers."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import IO

from pkgwatch.models import RejectionCode
from pkgwatch.sandbox.errors import reject

CHUNK_SIZE = 1 << 16


@dataclass(slots=True)
class WriteBudget:
    limit: int
    used: int = 0

    def add(self, amount: int) -> None:
        self.used += amount
        if self.used > self.limit:
            reject(
                RejectionCode.TOTAL_UNCOMPRESSED_EXCEEDED,
                "written bytes exceed max_total_uncompressed_bytes",
                limit_name="max_total_uncompressed_bytes",
                limit_value=float(self.limit),
                observed_value=float(self.used),
            )


def copy_exact(
    source: IO[bytes],
    destination: IO[bytes],
    expected: int,
    deadline: float,
    budget: WriteBudget,
) -> str:
    """Copy exactly ``expected`` bytes, returning the SHA-256 of what was written."""
    hasher = hashlib.sha256()
    copied = 0
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            break
        copied += len(chunk)
        if copied > expected:
            reject(
                RejectionCode.ARCHIVE_TRUNCATED,
                "member is larger than its declared size",
            )
        budget.add(len(chunk))
        hasher.update(chunk)
        destination.write(chunk)
        if time.monotonic() > deadline:
            reject(RejectionCode.DEADLINE_EXCEEDED, "extraction deadline exceeded")
    if copied != expected:
        reject(RejectionCode.ARCHIVE_TRUNCATED, "member ended before its declared size")
    return hasher.hexdigest()
