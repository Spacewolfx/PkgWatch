"""Turn committed fixture trees into a ``DiffContext`` through the real sandbox.

A fixture case is a directory holding ``old/`` and ``new/`` package trees (npm layout,
paths relative to the tarball root). An optional ``registry.json`` on a side is fed to
``metadata_before`` / ``metadata_after`` and stays out of the tree.

Nothing here installs, imports or runs package code: the trees are packed into a
synthetic tarball and unpacked by ``pkgwatch.sandbox`` exactly as production does.
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pkgwatch.diff import build_diff_context
from pkgwatch.models import DiffContext, Ecosystem, SandboxLimits
from pkgwatch.sandbox import extract_archive
from tests.support.archives import Entry, make_tar

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
RULE_FIXTURES = FIXTURES / "rules"
PACKAGE_FIXTURES = FIXTURES / "packages"

REGISTRY_FILE = "registry.json"
PUBLISHED = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)


def _side(case_dir: Path, name: str) -> tuple[list[Entry], dict[str, Any]]:
    root = case_dir / name
    if not root.is_dir():
        return [], {}
    entries: list[Entry] = []
    metadata: dict[str, Any] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        if relative == REGISTRY_FILE:
            metadata = json.loads(data)
            continue
        entries.append(Entry(f"package/{relative}", data))
    return entries, metadata


def context_from_case(
    tmp_path: Path,
    case_dir: Path,
    *,
    ecosystem: Ecosystem = Ecosystem.NPM,
    package_name: str = "demo-pkg",
    old_version: str = "1.0.0",
    new_version: str = "1.1.0",
    published_at: datetime = PUBLISHED,
    limits: SandboxLimits | None = None,
) -> DiffContext:
    active = limits or SandboxLimits()
    old_entries, metadata_before = _side(case_dir, "old")
    new_entries, metadata_after = _side(case_dir, "new")

    workdir = Path(tempfile.mkdtemp(dir=tmp_path))
    old_archive = make_tar(workdir / "old.tgz", old_entries)
    new_archive = make_tar(workdir / "new.tgz", new_entries)
    old_tree = extract_archive(old_archive, workdir / "extract" / "old", active)
    new_tree = extract_archive(new_archive, workdir / "extract" / "new", active)

    return build_diff_context(
        ecosystem=ecosystem,
        package_name=package_name,
        old_version=old_version,
        new_version=new_version,
        published_at=published_at,
        old=old_tree,
        new=new_tree,
        limits=active,
        metadata_before=metadata_before,
        metadata_after=metadata_after,
    )


def rule_context(tmp_path: Path, rule_id: str, polarity: str, **kwargs: Any) -> DiffContext:
    case = RULE_FIXTURES / rule_id / polarity
    if not case.is_dir():
        raise AssertionError(f"missing fixture for {rule_id}/{polarity}: {case}")
    return context_from_case(tmp_path, case, **kwargs)


def package_context(tmp_path: Path, case_name: str, **kwargs: Any) -> DiffContext:
    case = PACKAGE_FIXTURES / case_name
    if not case.is_dir():
        raise AssertionError(f"missing integration fixture: {case}")
    return context_from_case(tmp_path, case, **kwargs)
