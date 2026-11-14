"""One canonical JSON spelling, so a digest computed here equals one computed elsewhere."""

from __future__ import annotations

import hashlib
import json


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def digest_of(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
