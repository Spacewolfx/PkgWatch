"""Untrusted package-lock.json parsing (SPEC §9.1, L1)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from pkgwatch.config import LockConfig
from pkgwatch.lockfile import (
    LockEntry,
    LockfileError,
    LockfileErrorCode,
    SkipReason,
    parse_lockfile,
)

REGISTRY = "https://registry.npmjs.org"


def _write(tmp_path: Path, payload: Any) -> Path:
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_text(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "package-lock.json"
    path.write_text(text, encoding="utf-8")
    return path


def _lock(version: Any, packages: dict[str, Any]) -> dict[str, Any]:
    return {"lockfileVersion": version, "packages": packages}


@pytest.mark.parametrize("version", [2, 3])
def test_v2_and_v3_parse_dedupe_and_sort_by_name_and_version(tmp_path: Path, version: int) -> None:
    path = _write(
        tmp_path,
        _lock(
            version,
            {
                "": {"name": "app", "version": "9.9.9"},
                "node_modules/x/node_modules/b": {
                    "version": "2.0.0",
                    "resolved": f"{REGISTRY}/b/-/b-2.0.0.tgz",
                    "hasInstallScript": True,
                },
                "node_modules/b": {
                    "version": "2.0.0",
                    "resolved": f"{REGISTRY}/b/-/b-2.0.0.tgz",
                    "hasInstallScript": True,
                },
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": f"{REGISTRY}/a/-/a-1.0.0.tgz",
                },
            },
        ),
    )

    parsed = parse_lockfile(path, limits=LockConfig())

    assert parsed.lockfile_version == version
    assert parsed.entries == (
        LockEntry(name="a", version="1.0.0", resolved=f"{REGISTRY}/a/-/a-1.0.0.tgz"),
        LockEntry(
            name="b",
            version="2.0.0",
            resolved=f"{REGISTRY}/b/-/b-2.0.0.tgz",
            has_install_script=True,
        ),
    )
    assert parsed.skipped == ()


def test_names_come_from_nested_paths_explicit_name_or_are_rejected(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _lock(
            3,
            {
                "node_modules/@scope/pkg": {"version": "1.0.0"},
                "node_modules/outer/node_modules/inner": {"version": "2.0.0"},
                "node_modules/alias": {"name": "@real/pkg", "version": "3.0.0"},
                "node_modules/linked": {"version": "4.0.0", "link": True},
                "packages/workspace": {"name": "workspace", "version": "5.0.0"},
            },
        ),
    )

    parsed = parse_lockfile(path, limits=LockConfig())

    assert [entry.name for entry in parsed.entries] == [
        "@real/pkg",
        "@scope/pkg",
        "inner",
        "linked",
    ]
    assert parsed.entries[-1].link is True
    assert [(item.name, item.reason) for item in parsed.skipped] == [
        ("packages/workspace", SkipReason.UNSUPPORTED_PATH)
    ]


def test_invalid_entries_are_recorded_with_stable_reasons(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        _lock(
            3,
            {
                "node_modules/ok": {"version": "^1.0.0"},
                "node_modules/BadName": {"version": "1.0.0"},
                "node_modules/no-version": {},
                "node_modules/not-dict": "not a map",
                "node_modules/bad-install": {
                    "version": "1.0.0",
                    "hasInstallScript": "yes",
                },
            },
        ),
    )

    parsed = parse_lockfile(path, limits=LockConfig())

    assert parsed.entries == ()
    assert [(item.name, item.version, item.reason) for item in parsed.skipped] == [
        ("BadName", "1.0.0", SkipReason.INVALID_NAME),
        ("bad-install", "1.0.0", SkipReason.INVALID_ENTRY),
        ("no-version", None, SkipReason.INVALID_VERSION),
        ("not-dict", None, SkipReason.INVALID_ENTRY),
        ("ok", "^1.0.0", SkipReason.INVALID_VERSION),
    ]


@pytest.mark.parametrize("version", [1, 4, "3", True, None])
def test_unsupported_lockfile_versions_fail_with_a_stable_code(
    tmp_path: Path, version: Any
) -> None:
    path = _write(tmp_path, _lock(version, {}))

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_UNSUPPORTED_VERSION


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({"packages": {}}, id="missing-version"),
        pytest.param({"lockfileVersion": 3}, id="missing-packages"),
        pytest.param([3, {}], id="root-is-not-an-object"),
        pytest.param({"lockfileVersion": 3, "packages": []}, id="packages-is-not-a-map"),
    ],
)
def test_malformed_lockfile_shapes_fail_with_invalid_format(tmp_path: Path, payload: Any) -> None:
    path = _write(tmp_path, payload)

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_INVALID_FORMAT


def test_invalid_json_fails_with_a_stable_code(tmp_path: Path) -> None:
    path = _write_text(tmp_path, "{not json")

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_INVALID_JSON


def test_size_limit_is_checked_before_json_parsing(tmp_path: Path) -> None:
    path = _write_text(tmp_path, "{" + " " * 100 + "not json")

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig(max_lockfile_bytes=32))

    assert caught.value.code is LockfileErrorCode.LOCKFILE_TOO_LARGE


def test_depth_limit_is_checked_before_json_parsing(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {},
            "deep": [[[[1]]]],
        },
    )

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig(max_json_depth=3))

    assert caught.value.code is LockfileErrorCode.LOCKFILE_DEPTH_EXCEEDED


def test_depth_check_ignores_brackets_inside_strings(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        {
            "lockfileVersion": 3,
            "packages": {},
            "note": "[[[[[[[[[[ not nesting ]]]]]]]]]]",
        },
    )

    parsed = parse_lockfile(path, limits=LockConfig(max_json_depth=3))

    assert parsed.entries == ()


def test_a_missing_lockfile_fails_with_not_found(tmp_path: Path) -> None:
    with pytest.raises(LockfileError) as caught:
        parse_lockfile(tmp_path / "missing.json", limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_NOT_FOUND
    assert str(caught.value) == "LOCKFILE_NOT_FOUND"


def test_a_permission_error_fails_with_permission_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _deny(*args: Any, **kwargs: Any) -> Any:
        raise PermissionError("secret path detail")

    monkeypatch.setattr(Path, "open", _deny)

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(tmp_path / "old.json", limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_PERMISSION_DENIED
    assert str(caught.value) == "LOCKFILE_PERMISSION_DENIED"


def test_other_os_errors_keep_the_read_failed_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _broken(*args: Any, **kwargs: Any) -> Any:
        raise OSError("device detail that must never be printed")

    monkeypatch.setattr(Path, "open", _broken)

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(tmp_path / "old.json", limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_READ_FAILED
    assert str(caught.value) == "LOCKFILE_READ_FAILED"


def test_non_utf8_bytes_fail_with_not_utf8(tmp_path: Path) -> None:
    path = tmp_path / "package-lock.json"
    path.write_bytes(b"\xff\xfe{\x00")

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_NOT_UTF8
    assert str(caught.value) == "LOCKFILE_NOT_UTF8"


def test_a_utf8_bom_is_accepted_silently(tmp_path: Path) -> None:
    path = tmp_path / "package-lock.json"
    path.write_bytes(
        b"\xef\xbb\xbf"
        + json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/a": {
                        "version": "1.0.0",
                        "resolved": f"{REGISTRY}/a/-/a-1.0.0.tgz",
                    }
                },
            }
        ).encode("utf-8")
    )

    parsed = parse_lockfile(path, limits=LockConfig())

    assert parsed.lockfile_version == 3
    assert [entry.name for entry in parsed.entries] == ["a"]


def test_duplicate_json_keys_are_rejected_with_a_stable_code(tmp_path: Path) -> None:
    path = _write_text(
        tmp_path,
        '{"lockfileVersion": 3, "packages": {}, "packages": {}}',
    )

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_DUPLICATE_KEY


def test_a_duplicate_package_entry_is_not_silently_taking_the_last_value(tmp_path: Path) -> None:
    path = _write_text(
        tmp_path,
        (
            '{"lockfileVersion": 3, "packages": {'
            '"node_modules/a": {"version": "1.0.0"}, '
            '"node_modules/a": {"version": "2.0.0"}}}'
        ),
    )

    with pytest.raises(LockfileError) as caught:
        parse_lockfile(path, limits=LockConfig())

    assert caught.value.code is LockfileErrorCode.LOCKFILE_DUPLICATE_KEY


def test_integrity_is_retained_on_the_entry(tmp_path: Path) -> None:
    # C2a: the per-entry integrity hash must survive parsing so the plan can compare it.
    path = _write(
        tmp_path,
        _lock(
            3,
            {
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": f"{REGISTRY}/a/-/a-1.0.0.tgz",
                    "integrity": "sha512-AAAA",
                },
            },
        ),
    )

    parsed = parse_lockfile(path, limits=LockConfig())

    assert getattr(parsed.entries[0], "integrity", None) == "sha512-AAAA"


def test_a_non_string_integrity_is_an_invalid_entry(tmp_path: Path) -> None:
    # integrity is untrusted lockfile text; a non-string value must not reach the plan.
    path = _write(
        tmp_path,
        _lock(3, {"node_modules/a": {"version": "1.0.0", "integrity": 12345}}),
    )

    parsed = parse_lockfile(path, limits=LockConfig())

    assert parsed.entries == ()
    assert [(item.name, item.reason) for item in parsed.skipped] == [
        ("a", SkipReason.INVALID_ENTRY)
    ]


def test_a_conflicting_duplicate_identity_is_recorded_not_silently_dropped(
    tmp_path: Path,
) -> None:
    # C3: two paths map to the same (name, version) but disagree on the tarball source.
    # Keeping the first silently would hide the conflict; record a skip for the second.
    path = _write(
        tmp_path,
        _lock(
            3,
            {
                "node_modules/a": {
                    "version": "1.0.0",
                    "resolved": f"{REGISTRY}/a/-/a-1.0.0.tgz",
                },
                "node_modules/x/node_modules/a": {
                    "version": "1.0.0",
                    "resolved": f"{REGISTRY}/a/-/a-1.0.0-other.tgz",
                },
            },
        ),
    )

    parsed = parse_lockfile(path, limits=LockConfig())

    assert [entry.name for entry in parsed.entries] == ["a"]
    assert [(item.name, item.version, item.reason.value) for item in parsed.skipped] == [
        ("a", "1.0.0", "DUPLICATE_ENTRY")
    ]
