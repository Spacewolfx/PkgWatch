"""SPEC §6.3: a package is in exactly one split forever, salted and version-free."""

from __future__ import annotations

import hashlib

from pkgwatch.models import Split

SPLIT_SALT = "pkgwatch-split-v1"
TRAIN_MAX = 700
VAL_MAX = 850


def split_bucket(ecosystem: str, package_name: str) -> int:
    """The first 8 hex of SHA-256 over the salted identity, modulo 1000."""
    token = f"{SPLIT_SALT}|{ecosystem}|{package_name}"
    return int(hashlib.sha256(token.encode("utf-8")).hexdigest()[:8], 16) % 1000


def assign_split(ecosystem: str, package_name: str) -> Split:
    bucket = split_bucket(ecosystem, package_name)
    if bucket < TRAIN_MAX:
        return Split.TRAIN
    if bucket < VAL_MAX:
        return Split.VAL
    return Split.TEST
