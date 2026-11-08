from __future__ import annotations

import os
from pathlib import Path

from pkgwatch.models import SandboxLimits
from pkgwatch.sandbox import extract_archive
from tests.support.archives import Entry, make_tar


def test_output_tree_contains_no_links(tmp_path: Path) -> None:
    archive = make_tar(
        tmp_path / "pkg.tgz",
        [
            Entry("pkg/a.py", data=b"a"),
            Entry("pkg/sym.py", kind="symlink", linkname="a.py"),
            Entry("pkg/hard.py", kind="hardlink", linkname="pkg/a.py"),
            Entry("pkg/sub", kind="dir"),
        ],
    )
    root = tmp_path / "root"
    extract_archive(archive, root, SandboxLimits())

    visited = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = Path(dirpath) / name
            visited += 1
            assert not path.is_symlink()
            assert not os.path.islink(path)
            if path.is_file() and name != "hard.py":
                assert path.stat().st_nlink == 1
    assert visited >= 4
