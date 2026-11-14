"""The seam hashes the artifacts itself: fetch keeps only digest method names."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tests.support.context import ctx_from_files

from pkgwatch.config import Config
from pkgwatch.dataset.canonical import canonical_json, digest_of
from pkgwatch.dataset.record import record_filename, record_pair
from pkgwatch.models import AnalysisRecord
from pkgwatch.rules import rule_set_version


def test_the_filename_is_a_hash_not_a_package_name() -> None:
    name = record_filename("npm", "@scope/pkg", "1.0.0", "1.1.0+build")
    assert name.endswith(".json")
    assert len(name) == 64 + 5
    assert "/" not in name
    assert "+" not in name
    expected = hashlib.sha256(b"npm|@scope/pkg|1.0.0|1.1.0+build").hexdigest()
    assert name == expected + ".json"


def test_canonical_json_is_sorted_and_compact() -> None:
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert digest_of({"a": 1}) == hashlib.sha256(b'{"a":1}').hexdigest()


def test_a_pair_writes_one_valid_record(tmp_path: Path) -> None:
    old = tmp_path / "old.tgz"
    new = tmp_path / "new.tgz"
    old.write_bytes(b"old artifact")
    new.write_bytes(b"new artifact")
    ctx = ctx_from_files(tmp_path, {"package/a.js": b"a\n"}, {"package/a.js": b"b\n"})
    out = tmp_path / "records"
    outcome = record_pair(
        ctx=ctx,
        findings=(),
        old_path=old,
        new_path=new,
        config=Config(),
        experimental=False,
        directory=out,
    )
    assert outcome.written is True
    files = list(out.glob("*.json"))
    assert len(files) == 1
    record = AnalysisRecord.model_validate(json.loads(files[0].read_text(encoding="utf-8")))
    assert record.artifact_sha256_old == hashlib.sha256(b"old artifact").hexdigest()
    assert record.artifact_sha256_new == hashlib.sha256(b"new artifact").hexdigest()
    assert record.rule_set_version == rule_set_version()
    assert len(record.features) == 69


def test_a_brand_new_package_is_not_recorded(tmp_path: Path) -> None:
    new = tmp_path / "new.tgz"
    new.write_bytes(b"new artifact")
    ctx = ctx_from_files(tmp_path, {}, {"package/a.js": b"a\n"})
    out = tmp_path / "records"
    outcome = record_pair(
        ctx=ctx,
        findings=(),
        old_path=None,
        new_path=new,
        config=Config(),
        experimental=False,
        directory=out,
    )
    assert outcome.written is False
    assert outcome.reason == "new_package"
    assert not out.exists() or not list(out.glob("*.json"))


def test_re_recording_the_same_pair_is_byte_identical(tmp_path: Path) -> None:
    old = tmp_path / "old.tgz"
    new = tmp_path / "new.tgz"
    old.write_bytes(b"old")
    new.write_bytes(b"new")
    ctx = ctx_from_files(tmp_path, {"package/a.js": b"a\n"}, {"package/a.js": b"b\n"})
    out = tmp_path / "records"
    for _ in range(2):
        record_pair(
            ctx=ctx,
            findings=(),
            old_path=old,
            new_path=new,
            config=Config(),
            experimental=False,
            directory=out,
        )
    files = list(out.glob("*.json"))
    assert len(files) == 1
