"""Build and safely extract a synthetic package tree, returning its manifest."""

from __future__ import annotations

from pathlib import Path

from pkgwatch.models import ExtractionResult, SandboxLimits
from pkgwatch.sandbox import extract_archive
from tests.support.archives import Entry, make_tar


def extract_tree(
    tmp_path: Path,
    name: str,
    entries: list[Entry],
    limits: SandboxLimits | None = None,
) -> ExtractionResult:
    archive = make_tar(tmp_path / f"{name}.tgz", entries)
    target = tmp_path / "extract" / name
    return extract_archive(archive, target, limits or SandboxLimits())
