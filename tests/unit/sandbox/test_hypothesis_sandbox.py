from __future__ import annotations

import os
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from pkgwatch.models import SandboxLimits
from pkgwatch.sandbox import ArchiveRejected, extract_archive
from tests.support.archives import Entry, make_tar

NAME_ALPHABET = "abcXYZ0123/._-\\: ~\u00e9@"

entry_strategy = st.builds(
    Entry,
    name=st.text(alphabet=NAME_ALPHABET, min_size=0, max_size=24),
    data=st.just(b"payload"),
)


@given(entries=st.lists(entry_strategy, min_size=1, max_size=6))
def test_no_write_ever_lands_outside_the_root(tmp_path: Path, entries: list[Entry]) -> None:
    # Hypothesis reuses the function-scoped tmp_path for every example, so each
    # example gets its own case directory.
    case = Path(tempfile.mkdtemp(dir=tmp_path))
    archive = make_tar(case / "pkg.tgz", entries)
    sentinel = case / "sentinel.txt"
    sentinel.write_text("keep", encoding="utf-8")
    before = {path.name for path in case.iterdir()}
    root = case / "root"

    try:
        result = extract_archive(archive, root, SandboxLimits())
    except ArchiveRejected:
        assert not root.exists()
        assert not list(case.glob(".tmp-*"))
        assert sentinel.read_text(encoding="utf-8") == "keep"
        assert {path.name for path in case.iterdir()} == before
        return

    assert sentinel.read_text(encoding="utf-8") == "keep"
    resolved_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            path = Path(dirpath) / name
            assert path.resolve().is_relative_to(resolved_root)
            assert not path.is_symlink()

    for entry in result.entries:
        assert ".." not in entry.path.split("/")
        assert not entry.path.startswith("/")
    assert {path.name for path in case.iterdir()} == before | {"root"}
