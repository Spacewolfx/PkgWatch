"""Pure-function and transport tests for ``pkgwatch.fetch.npm`` (offline only)."""

from __future__ import annotations

import base64
import hashlib
import http.server
import threading
from pathlib import Path
from typing import Any, ClassVar

import pytest

from pkgwatch.fetch.npm import (
    FetchError,
    FetchErrorCode,
    UrllibClient,
    build_doc_url,
    expected_digest,
    is_registry_url,
    parse_spec,
    verify_digest,
)
from pkgwatch.models import RejectionCode
from tests.support.archives import Entry, make_tar
from tests.support.npm_registry import dist_for

SOURCE_ROOT = Path(__file__).resolve().parents[3] / "src" / "pkgwatch"


def test_parse_spec_accepts_unscoped_and_scoped_exact_versions() -> None:
    assert parse_spec("npm:demo-pkg@1.0.0") == ("demo-pkg", "1.0.0")
    assert parse_spec("npm:@scope/pkg@1.2.3-beta.1+build.5") == (
        "@scope/pkg",
        "1.2.3-beta.1+build.5",
    )


def test_build_doc_url_percent_encodes_a_scoped_name() -> None:
    assert build_doc_url("demo-pkg") == "https://registry.npmjs.org/demo-pkg"
    assert build_doc_url("@scope/pkg") == "https://registry.npmjs.org/@scope%2Fpkg"


@pytest.mark.parametrize(
    ("spec", "code"),
    [
        ("pypi:demo-pkg@1.0.0", FetchErrorCode.INVALID_SPEC),
        ("npm:demo-pkg", FetchErrorCode.INVALID_SPEC),
        ("npm:demo-pkg@", FetchErrorCode.INVALID_SPEC),
        ("npm:@scope/pkg", FetchErrorCode.INVALID_SPEC),
        ("npm:Demo-Pkg@1.0.0", FetchErrorCode.INVALID_PACKAGE_NAME),
        ("npm:demo pkg@1.0.0", FetchErrorCode.INVALID_PACKAGE_NAME),
        ("npm:../evil@1.0.0", FetchErrorCode.INVALID_PACKAGE_NAME),
        ("npm:demo%2Fpkg@1.0.0", FetchErrorCode.INVALID_PACKAGE_NAME),
        ("npm:demo-pkg@latest", FetchErrorCode.INVALID_VERSION),
        ("npm:demo-pkg@^1.0.0", FetchErrorCode.INVALID_VERSION),
        ("npm:demo-pkg@~1.0", FetchErrorCode.INVALID_VERSION),
        ("npm:demo-pkg@1.x", FetchErrorCode.INVALID_VERSION),
        ("npm:demo-pkg@>=1.0.0", FetchErrorCode.INVALID_VERSION),
        ("npm:demo-pkg@1.0", FetchErrorCode.INVALID_VERSION),
        ("npm:demo-pkg@*", FetchErrorCode.INVALID_VERSION),
    ],
)
def test_invalid_specs_are_rejected(spec: str, code: FetchErrorCode) -> None:
    with pytest.raises(FetchError) as exc:
        parse_spec(spec)
    assert exc.value.code is code


def test_is_registry_url_allows_only_https_on_the_registry_host() -> None:
    assert is_registry_url("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz")
    assert not is_registry_url("http://registry.npmjs.org/pkg")
    assert not is_registry_url("https://evil.example.org/pkg")
    assert not is_registry_url("https://registry.npmjs.org:8443/pkg")
    assert not is_registry_url("https://user@registry.npmjs.org/pkg")


def test_verify_digest_prefers_integrity_even_when_shasum_is_wrong() -> None:
    payload = b"synthetic payload"
    assert verify_digest(payload, {**dist_for(payload), "shasum": "0" * 40}) == "integrity"


def test_verify_digest_falls_back_to_shasum_only_without_integrity() -> None:
    payload = b"synthetic payload"
    assert verify_digest(payload, dist_for(payload, method="shasum")) == "shasum"


def test_verify_digest_reports_mismatch_missing_and_unsupported() -> None:
    payload = b"synthetic payload"

    with pytest.raises(FetchError) as mismatch:
        verify_digest(payload, dist_for(payload, corrupt=True))
    assert mismatch.value.code is FetchErrorCode.DIGEST_MISMATCH

    with pytest.raises(FetchError) as shasum_mismatch:
        verify_digest(payload, {"shasum": "0" * 40})
    assert shasum_mismatch.value.code is FetchErrorCode.DIGEST_MISMATCH

    with pytest.raises(FetchError) as missing:
        verify_digest(payload, dist_for(payload, method="none"))
    assert missing.value.code is FetchErrorCode.DIGEST_MISSING

    with pytest.raises(FetchError) as unsupported:
        verify_digest(payload, {"integrity": "sha256-AAAA"})
    assert unsupported.value.code is FetchErrorCode.DIGEST_UNSUPPORTED


def test_verify_digest_accepts_a_valid_sri_sha512() -> None:
    payload = b"synthetic payload"
    sri = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
    assert verify_digest(payload, {"integrity": sri}) == "integrity"


def test_sri_sha512_with_wrong_decoded_length_is_unsupported() -> None:
    # A sha512 SRI must decode to exactly 64 bytes; a short decode would otherwise
    # produce a truncated cache key and a misleading DIGEST_MISMATCH.
    short = "sha512-" + base64.b64encode(b"12345").decode("ascii")
    with pytest.raises(FetchError) as excinfo:
        expected_digest({"integrity": short})
    assert excinfo.value.code is FetchErrorCode.DIGEST_UNSUPPORTED


def test_digest_mismatch_token_matches_the_spec_rejection_code() -> None:
    assert FetchErrorCode.DIGEST_MISMATCH.value == RejectionCode.DIGEST_MISMATCH.value


def test_compare_path_never_reads_archives_directly() -> None:
    for relative in ("cli.py", "fetch/npm.py"):
        text = (SOURCE_ROOT / relative).read_text(encoding="utf-8")
        assert "tarfile" not in text, relative
        assert "zipfile" not in text, relative


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    seen_agents: ClassVar[list[str | None]] = []

    def do_GET(self) -> None:
        _RedirectHandler.seen_agents.append(self.headers.get("User-Agent"))
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/landed")
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"landed")

    def log_message(self, format: str, *args: Any) -> None:
        return


def test_default_transport_does_not_follow_redirects_and_sets_a_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A local 127.0.0.1 server: the real transport must surface 3xx, not follow it."""
    for key in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.delenv(key, raising=False)
    _RedirectHandler.seen_agents = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _RedirectHandler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/start"
        response = UrllibClient().get(url, user_agent="pkgwatch/test", timeout=5.0, max_bytes=64)
        assert response.status == 302
        assert response.headers["location"] == "/landed"
        assert _RedirectHandler.seen_agents == ["pkgwatch/test"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_tarball_builder_stays_synthetic(tmp_path: Path) -> None:
    """A fixture tarball is a real gzip archive, built only from committed fixture trees."""
    archive = make_tar(tmp_path / "synthetic.tgz", [Entry("package/index.js", b"var x = 1;\n")])
    assert archive.read_bytes()[:2] == b"\x1f\x8b"
