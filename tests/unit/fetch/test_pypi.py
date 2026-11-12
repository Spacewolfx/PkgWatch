"""PyPI fetch layer: document URL, PEP 503 names, host allowlist, artifact selection.

Everything is served by the offline ``PyPIRegistry`` double; no test touches the network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pkgwatch.config import Config
from pkgwatch.fetch.npm import FetchError, FetchErrorCode
from pkgwatch.fetch.pypi import (
    _filename_leaf,
    build_doc_url,
    fetch_pair_pypi,
    is_pypi_url,
    normalize_name,
    parse_spec,
    validate_name_pypi,
)
from tests.support.pypi_registry import (
    PyPIRegistry,
    pypi_pair_registry,
    sdist_bytes,
    wheel_bytes,
)

CONFIG = Config()


def _fetch(tmp_path: Path, registry: PyPIRegistry):  # type: ignore[no-untyped-def]
    workdir = tmp_path / "work"
    workdir.mkdir(exist_ok=True)
    return fetch_pair_pypi(
        name=registry.name,
        old_version="1.0.0",
        new_version="1.1.0",
        config=CONFIG,
        client=registry,
        workdir=workdir,
    )


@pytest.mark.parametrize(
    ("name", "normalized"),
    [("foo-bar", "foo-bar"), ("Foo_Bar", "foo-bar"), ("foo.bar", "foo-bar"), ("A__B..C", "a-b-c")],
)
def test_pep503_normalization(name: str, normalized: str) -> None:
    assert normalize_name(name) == normalized


def test_doc_url_uses_the_normalized_name() -> None:
    assert build_doc_url("Foo_Bar") == "https://pypi.org/pypi/foo-bar/json"


@pytest.mark.parametrize("name", ["foo", "foo.bar", "Foo_Bar", "f1", "a-b", "x" * 100])
def test_valid_names(name: str) -> None:
    validate_name_pypi(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "-foo",
        "foo-",
        ".foo",
        "foo.",
        "foo/bar",
        "foo\\bar",
        "..",
        "foo bar",
        "foo\x00bar",
        "föö",
        "x" * 215,
    ],
)
def test_invalid_names(name: str) -> None:
    with pytest.raises(FetchError) as caught:
        validate_name_pypi(name)
    assert caught.value.code is FetchErrorCode.INVALID_PACKAGE_NAME


def test_parse_spec_accepts_only_the_pypi_prefix() -> None:
    assert parse_spec("pypi:foo@1.0") == ("foo", "1.0")
    assert parse_spec("pypi:Foo_Bar@2!1.0.post1") == ("Foo_Bar", "2!1.0.post1")


@pytest.mark.parametrize(
    "text",
    ["npm:foo@1.0.0", "foo@1.0.0", "pypi:foo", "pypi:@1.0", "pypi:foo@", "pypi:foo@bogus"],
)
def test_parse_spec_rejects_everything_else(text: str) -> None:
    with pytest.raises(FetchError):
        parse_spec(text)


@pytest.mark.parametrize(
    ("url", "allowed"),
    [
        ("https://pypi.org/pypi/foo/json", True),
        ("https://files.pythonhosted.org/packages/aa/bb/foo.tar.gz", True),
        ("http://pypi.org/pypi/foo/json", False),
        ("https://evil.example/foo.tar.gz", False),
        ("https://pypi.org:8443/pypi/foo/json", False),
        ("https://user@pypi.org/pypi/foo/json", False),
        ("https://pypi.org.evil.example/foo", False),
    ],
)
def test_host_allowlist(url: str, allowed: bool) -> None:
    assert is_pypi_url(url) is allowed


def test_sdist_is_preferred_over_wheel(tmp_path: Path) -> None:
    registry = PyPIRegistry(name="demo")
    old = sdist_bytes(tmp_path, "demo", "1.0.0", {"demo/__init__.py": b""})
    new = sdist_bytes(tmp_path, "demo", "1.1.0", {"demo/__init__.py": b""})
    wheel = wheel_bytes(tmp_path, "demo", "1.1.0", {"demo/__init__.py": b""})
    registry.add_release("1.0.0", old)
    # The wheel is listed first; the sdist must still win.
    registry.add_release("1.1.0", wheel, packagetype="bdist_wheel")
    registry.add_release("1.1.0", new, packagetype="sdist")

    pair = _fetch(tmp_path, registry)

    assert pair.new.path.name.endswith(".tar.gz")
    assert pair.new.digest_method == "sha256"
    assert pair.old.path.name.endswith(".tar.gz")


def test_wheel_only_version_is_used(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={"demo/__init__.py": b""},
        new_files={"demo/__init__.py": b""},
        old_packagetype="bdist_wheel",
        new_packagetype="bdist_wheel",
    )

    pair = _fetch(tmp_path, registry)

    assert pair.old.path.name.endswith(".whl")
    assert pair.new.path.name.endswith(".whl")


def test_published_at_comes_from_the_file_entry(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
    )

    pair = _fetch(tmp_path, registry)

    assert pair.old.published_at.isoformat().startswith("2026-11-01")
    assert pair.new.published_at.isoformat().startswith("2026-11-05")


def test_version_without_usable_files_is_artifact_unavailable(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
    )
    registry.releases["1.1.0"] = [
        {
            "filename": "demo-1.1.0.egg",
            "url": registry.artifact_url("demo-1.1.0.egg"),
            "packagetype": "egg",
            "digests": {"sha256": "0" * 64},
        }
    ]

    with pytest.raises(FetchError) as caught:
        _fetch(tmp_path, registry)

    assert caught.value.code is FetchErrorCode.ARTIFACT_UNAVAILABLE


def test_unknown_version_is_version_not_found(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
    )
    del registry.releases["1.1.0"]

    with pytest.raises(FetchError) as caught:
        _fetch(tmp_path, registry)

    assert caught.value.code is FetchErrorCode.VERSION_NOT_FOUND


def test_artifact_url_off_the_allowlist_is_rejected(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
    )
    entry = registry.releases["1.1.0"][0]
    del registry.artifacts[entry["url"]]
    entry["url"] = "https://evil.example/demo-1.1.0.tar.gz"

    with pytest.raises(FetchError) as caught:
        _fetch(tmp_path, registry)

    assert caught.value.code is FetchErrorCode.TARBALL_URL_INVALID


@pytest.mark.parametrize(
    ("digest", "code"),
    [
        ("none", FetchErrorCode.DIGEST_MISSING),
        ("md5", FetchErrorCode.DIGEST_UNSUPPORTED),
        ("corrupt", FetchErrorCode.DIGEST_MISMATCH),
    ],
)
def test_digest_failures_use_stable_codes(
    tmp_path: Path, digest: str, code: FetchErrorCode
) -> None:
    registry = PyPIRegistry(name="demo")
    old = sdist_bytes(tmp_path, "demo", "1.0.0", {})
    new = sdist_bytes(tmp_path, "demo", "1.1.0", {})
    registry.add_release("1.0.0", old)
    registry.add_release("1.1.0", new, digest=digest)

    with pytest.raises(FetchError) as caught:
        _fetch(tmp_path, registry)

    assert caught.value.code is code


def test_blake2b_only_digest_is_accepted(tmp_path: Path) -> None:
    registry = PyPIRegistry(name="demo")
    old = sdist_bytes(tmp_path, "demo", "1.0.0", {})
    new = sdist_bytes(tmp_path, "demo", "1.1.0", {})
    registry.add_release("1.0.0", old)
    registry.add_release("1.1.0", new, digest="blake2b_256")

    pair = _fetch(tmp_path, registry)

    assert pair.new.digest_method == "blake2b_256"


def test_redirect_off_the_allowlist_is_rejected(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
    )
    url = registry.releases["1.1.0"][0]["url"]
    registry.redirects[url] = "https://evil.example/payload"

    with pytest.raises(FetchError) as caught:
        _fetch(tmp_path, registry)

    assert caught.value.code is FetchErrorCode.REDIRECT_REJECTED


def test_malformed_document_is_registry_doc_invalid(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
    )
    registry.doc_override = b"{not json"

    with pytest.raises(FetchError) as caught:
        _fetch(tmp_path, registry)

    assert caught.value.code is FetchErrorCode.REGISTRY_DOC_INVALID


def test_document_endpoints_are_on_pypi_org_artifacts_on_files_host(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
    )

    _fetch(tmp_path, registry)

    # The project doc and both per-version docs are on pypi.org; only the two
    # artifacts are on files.pythonhosted.org.
    assert registry.requests[0] == "https://pypi.org/pypi/demo/json"
    artifacts = [r for r in registry.requests if r.startswith("https://files.pythonhosted.org/")]
    assert len(artifacts) == 2
    assert all(
        r.startswith(("https://pypi.org/", "https://files.pythonhosted.org/"))
        for r in registry.requests
    )


def test_build_version_doc_url_normalizes_the_name(tmp_path: Path) -> None:
    from pkgwatch.fetch.pypi import build_version_doc_url

    assert build_version_doc_url("Foo_Bar", "1.0") == "https://pypi.org/pypi/foo-bar/1.0/json"


def test_version_metadata_is_extracted_from_the_per_version_document(tmp_path: Path) -> None:
    registry = pypi_pair_registry(
        tmp_path,
        "demo",
        old_version="1.0.0",
        new_version="1.1.0",
        old_files={},
        new_files={},
        new_requires=("requests>=2.0",),
    )

    pair = _fetch(tmp_path, registry)

    assert pair.new.metadata["requires_dist"] == ["requests>=2.0"]
    assert "requires_dist" not in pair.old.metadata


def test_version_metadata_degrades_to_empty_when_unavailable(tmp_path: Path) -> None:
    """A version document that cannot be fetched yields {} (offline), never an error."""
    from pkgwatch.fetch.npm import HttpResponse
    from pkgwatch.fetch.pypi import _version_metadata

    class Offline:
        def get(self, url: str, **kwargs: object) -> HttpResponse:
            return HttpResponse(status=404, headers={}, body=b"")

    assert _version_metadata(Offline(), "demo", "1.0.0", CONFIG) == {}


@pytest.mark.parametrize(
    "filename",
    [
        "x:y.tar.gz",  # NTFS alternate data stream
        "a\x01b.tar.gz",  # control character
        "a b.tar.gz",  # space
        "a$b.tar.gz",  # outside the allowlist
        "evil.tar.gz.",  # trailing dot
        "a" * 300 + ".tar.gz",  # over-long component
        "..",
        "a/b.tar.gz",
        "a\\b.tar.gz",
    ],
)
def test_filename_leaf_rejects_unsafe_names(filename: str) -> None:
    with pytest.raises(FetchError) as excinfo:
        _filename_leaf({"filename": filename}, "https://files.pythonhosted.org/x/y")
    assert excinfo.value.code is FetchErrorCode.REGISTRY_DOC_INVALID


@pytest.mark.parametrize(
    "filename",
    [
        "demo-1.0.0.tar.gz",
        "demo-1.0.0-py3-none-any.whl",
        "foo_bar-1.0.tar.gz",
        "pkg+local-1.0.tar.gz",
    ],
)
def test_filename_leaf_accepts_realistic_names(filename: str) -> None:
    assert _filename_leaf({"filename": filename}, "https://files.pythonhosted.org/x/y") == filename
