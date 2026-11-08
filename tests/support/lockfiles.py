"""Synthetic package-lock.json files for offline lock tests.

The ``resolved`` URLs come from the offline registry stand-in, so a lockfile written here
always points at exactly what the injected client serves. No network, no real registry.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tests.support.npm_registry import FakeRegistry, resolved_url


def node_modules(name: str) -> str:
    return f"node_modules/{name}"


def registry_entry(registry: FakeRegistry, version: str, **extra: Any) -> dict[str, Any]:
    """One v2/v3 ``packages`` entry for a version the offline registry serves."""
    return {"version": version, "resolved": resolved_url(registry, version), **extra}


def write_lockfile(path: Path, packages: dict[str, Any], *, lockfile_version: int = 3) -> Path:
    path.write_text(
        json.dumps({"lockfileVersion": lockfile_version, "packages": packages}),
        encoding="utf-8",
    )
    return path
