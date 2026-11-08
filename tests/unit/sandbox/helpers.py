from __future__ import annotations

from pathlib import Path

import pytest

from pkgwatch.models import RejectionCode, SandboxLimits
from pkgwatch.sandbox import ArchiveRejected, extract_archive
from tests.support.archives import Entry, make_tar, make_zip


def assert_rejected(
    tmp_path: Path,
    entries: list[Entry],
    code: RejectionCode,
    *,
    as_zip: bool = False,
    **limit_overrides: object,
) -> ArchiveRejected:
    limits = SandboxLimits(**limit_overrides)
    archive = (
        make_zip(tmp_path / "pkg.zip", entries)
        if as_zip
        else make_tar(tmp_path / "pkg.tgz", entries)
    )
    with pytest.raises(ArchiveRejected) as excinfo:
        extract_archive(archive, tmp_path / "root", limits)
    assert excinfo.value.rejection.reason_code is code
    assert not (tmp_path / "root").exists()
    assert not list(tmp_path.glob(".tmp-*"))
    return excinfo.value
