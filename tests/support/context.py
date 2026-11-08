"""Build a ``DiffContext`` straight from in-memory file maps, through the sandbox."""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pkgwatch.diff import build_diff_context
from pkgwatch.models import DiffContext, Ecosystem, ObfuscationLimits, SandboxLimits
from pkgwatch.sandbox import extract_archive
from tests.support.archives import Entry, make_tar

PUBLISHED = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def ctx_from_files(
    tmp_path: Path,
    old_files: dict[str, bytes],
    new_files: dict[str, bytes],
    *,
    package_name: str = "demo-pkg",
    ecosystem: Ecosystem = Ecosystem.NPM,
    old_version: str = "1.0.0",
    new_version: str = "1.1.0",
    limits: SandboxLimits | None = None,
    metadata_before: dict[str, Any] | None = None,
    metadata_after: dict[str, Any] | None = None,
    obfuscation: ObfuscationLimits | None = None,
) -> DiffContext:
    active = limits or SandboxLimits()
    workdir = Path(tempfile.mkdtemp(dir=tmp_path))
    old_tree = extract_archive(
        make_tar(workdir / "old.tgz", [Entry(name, data) for name, data in old_files.items()]),
        workdir / "extract" / "old",
        active,
    )
    new_tree = extract_archive(
        make_tar(workdir / "new.tgz", [Entry(name, data) for name, data in new_files.items()]),
        workdir / "extract" / "new",
        active,
    )
    return build_diff_context(
        ecosystem=ecosystem,
        package_name=package_name,
        old_version=old_version,
        new_version=new_version,
        published_at=PUBLISHED,
        old=old_tree,
        new=new_tree,
        limits=active,
        metadata_before=metadata_before or {},
        metadata_after=metadata_after or {},
        obfuscation=obfuscation,
    )
