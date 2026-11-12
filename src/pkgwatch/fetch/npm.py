"""npm metadata and tarball fetching for the v0.1 ``compare`` command.

Only the SPEC §3 npm document endpoint is constructed here:
``GET https://registry.npmjs.org/<name>``. The tarball URL is read from that document's
``versions[v].dist.tarball``; it is never invented. Both URLs, and every redirect hop,
are restricted to HTTPS on the registry host.

Package bytes are hostile input: they are written to a temp file, hashed, and handed to
``pkgwatch.sandbox``. Nothing here decompresses, parses as source, or runs package content.

TODO(v0.1): the live registry's response shape beyond SPEC §3's listed fields, its
redirect behaviour for tarballs, and its rate limits were NOT verified offline.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast

from pkgwatch.config import Config
from pkgwatch.fetch.cache import DownloadCache, ExpectedDigest, digest_matches
from pkgwatch.models import Ecosystem
from pkgwatch.version import UnsupportedVersion
from pkgwatch.version import parse as parse_version

# SPEC §3: "GET https://registry.npmjs.org/<name>" (full package doc, 200 verified
# 2026-11-05). Scoped names use the %2F form, also stated in SPEC §3.
NPM_REGISTRY_HOST = "registry.npmjs.org"
NPM_DOC_URL_TEMPLATE = "https://registry.npmjs.org/{name}"

# Only the registry host is allowed, for the document, the tarball and every redirect.
# TODO(v0.1): npm tarballs may be served through a CDN on the live registry. Unverified
# offline; if a first smoke test sees a cross-host redirect, decide the allow-list then.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SRI_PREFIX = "sha512-"
_SHA512_BYTES = 64
_SPEC_PREFIX = "npm:"
MAX_NAME_LENGTH = 214
MAX_VERSION_LENGTH = 128

_NAME_RE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")

# TB1: only the SPEC §3 manifest-shaped fields reach the diff. ``dist`` is consumed here
# by the downloader and never handed to rules; unknown document fields are dropped.
_CONSUMED_VERSION_FIELDS = (
    "name",
    "version",
    "dependencies",
    "devDependencies",
    "scripts",
    "engines",
    "os",
    "cpu",
    "bin",
    "deprecated",
    # v0.2 "registry metadata changes" shows SPEC §3's dist.* size/telemetry fields.
    "dist",
)

# TODO(v0.1): a document with no parseable time[v] gets this fixed instant. No M2 rule
# reads published_at and it is never printed, so the run stays deterministic. Confirm
# npm always returns time[v] before any later milestone depends on it.
UNKNOWN_PUBLISHED_AT = datetime(1970, 1, 1, tzinfo=UTC)


class FetchErrorCode(StrEnum):
    """Stable codes printed by the CLI instead of exception messages (hostile input)."""

    INVALID_SPEC = "INVALID_SPEC"
    INVALID_PACKAGE_NAME = "INVALID_PACKAGE_NAME"
    INVALID_VERSION = "INVALID_VERSION"
    PACKAGE_MISMATCH = "PACKAGE_MISMATCH"
    REGISTRY_DOC_INVALID = "REGISTRY_DOC_INVALID"
    VERSION_NOT_FOUND = "VERSION_NOT_FOUND"
    TARBALL_URL_INVALID = "TARBALL_URL_INVALID"
    REDIRECT_REJECTED = "REDIRECT_REJECTED"
    SIZE_LIMIT_EXCEEDED = "SIZE_LIMIT_EXCEEDED"
    HTTP_ERROR = "HTTP_ERROR"
    FETCH_FAILED = "FETCH_FAILED"
    # Same stable token as SPEC §6.5's sandbox rejection code.
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    DIGEST_MISSING = "DIGEST_MISSING"
    DIGEST_UNSUPPORTED = "DIGEST_UNSUPPORTED"
    # PyPI: the version exists in the document but offers no sdist/wheel file.
    ARTIFACT_UNAVAILABLE = "ARTIFACT_UNAVAILABLE"


class FetchError(Exception):
    """Carries a stable code only. The message never contains package-controlled text."""

    def __init__(self, code: FetchErrorCode) -> None:
        super().__init__(code.value)
        self.code = code


class FetchTimeout(FetchError):
    """A transport timeout; the stable code stays ``FETCH_FAILED``.

    The retry wrapper needs to tell a timeout apart from a permanent failure without
    changing any code the CLI prints.
    """

    def __init__(self) -> None:
        super().__init__(FetchErrorCode.FETCH_FAILED)


@dataclass(frozen=True)
class HttpResponse:
    """One transport response. ``body`` is already bounded by ``max_bytes``."""

    status: int
    headers: Mapping[str, str]
    body: bytes


class HttpClient(Protocol):
    """Injectable transport; tests supply a local, offline implementation."""

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse: ...


@dataclass(frozen=True)
class VersionArtifact:
    version: str
    path: Path
    digest_method: str
    size: int
    metadata: dict[str, Any]
    published_at: datetime


@dataclass(frozen=True)
class FetchPair:
    name: str
    old: VersionArtifact
    new: VersionArtifact


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Our own redirect policy decides; urllib surfaces 3xx as an HTTPError."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class UrllibClient:
    """One GET at a time, with a hard read cap and no automatic redirects."""

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        request = urllib.request.Request(  # noqa: S310 - https + registry host checked by caller
            url, headers={"User-Agent": user_agent}
        )
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(request, timeout=timeout) as response:
                status = int(response.status)
                headers = {key.lower(): str(value) for key, value in response.headers.items()}
                body = bytes(response.read(max_bytes))
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            headers = {key.lower(): str(value) for key, value in exc.headers.items()}
            body = b""
        except (urllib.error.URLError, OSError, ValueError) as exc:
            if _is_timeout(exc):
                raise FetchTimeout() from None
            raise FetchError(FetchErrorCode.FETCH_FAILED) from None
        return HttpResponse(status=status, headers=headers, body=body)


def _is_timeout(error: BaseException) -> bool:
    return isinstance(error, TimeoutError) or isinstance(
        getattr(error, "reason", None), TimeoutError
    )


def validate_name(name: str) -> None:
    """Reject anything that is not an exact npm name, before a URL can be built."""
    if not name or len(name) > MAX_NAME_LENGTH or not _NAME_RE.fullmatch(name) or ".." in name:
        raise FetchError(FetchErrorCode.INVALID_PACKAGE_NAME)


def validate_version(version: str) -> None:
    """Exact versions only. Ranges, tags, wildcards and partial versions are refused.

    Delegates to the SPEC §6.4 parser so the acceptance grammar has one source of
    truth; the parser's npm grammar is the shape this function has always accepted.
    """
    if not version or len(version) > MAX_VERSION_LENGTH:
        raise FetchError(FetchErrorCode.INVALID_VERSION)
    try:
        parse_version(Ecosystem.NPM, version)
    except UnsupportedVersion:
        raise FetchError(FetchErrorCode.INVALID_VERSION) from None


def parse_spec(text: str) -> tuple[str, str]:
    """Split ``npm:<name>@<version>``. The last ``@`` separates a scoped name correctly."""
    if not text.startswith(_SPEC_PREFIX):
        raise FetchError(FetchErrorCode.INVALID_SPEC)
    body = text[len(_SPEC_PREFIX) :]
    separator = body.rfind("@")
    if separator <= 0 or separator == len(body) - 1:
        raise FetchError(FetchErrorCode.INVALID_SPEC)
    name = body[:separator]
    version = body[separator + 1 :]
    validate_name(name)
    validate_version(version)
    return name, version


def build_doc_url(name: str) -> str:
    """The only URL pkgwatch constructs itself; validation happens first."""
    validate_name(name)
    return NPM_DOC_URL_TEMPLATE.format(name=urllib.parse.quote(name, safe="@"))


def is_registry_url(url: str) -> bool:
    """HTTPS on the registry host only: no userinfo, no alternative port, no plain HTTP."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.hostname == NPM_REGISTRY_HOST
        and port in (None, 443)
        and parts.username is None
        and parts.password is None
    )


def expected_digest(dist: Mapping[str, Any]) -> ExpectedDigest:
    """Decode the registry's SRI integrity, else the legacy shasum, as a cache key.

    The result is always hex, so a package-controlled value is never used as a path.
    """
    integrity = dist.get("integrity")
    if isinstance(integrity, str) and integrity.strip():
        if not integrity.startswith(_SRI_PREFIX):
            raise FetchError(FetchErrorCode.DIGEST_UNSUPPORTED)
        try:
            expected = base64.b64decode(integrity[len(_SRI_PREFIX) :], validate=True)
        except (binascii.Error, ValueError):
            raise FetchError(FetchErrorCode.DIGEST_UNSUPPORTED) from None
        if len(expected) != _SHA512_BYTES:
            raise FetchError(FetchErrorCode.DIGEST_UNSUPPORTED)
        return ExpectedDigest(method="integrity", algorithm="sha512", hexdigest=expected.hex())

    shasum = dist.get("shasum")
    if isinstance(shasum, str) and shasum.strip():
        # npm's legacy dist.shasum is SHA-1, used only when integrity is absent.
        value = shasum.strip().lower()
        if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
            raise FetchError(FetchErrorCode.DIGEST_MISMATCH)
        return ExpectedDigest(method="shasum", algorithm="sha1", hexdigest=value)

    raise FetchError(FetchErrorCode.DIGEST_MISSING)


def verify_digest(data: bytes, dist: Mapping[str, Any]) -> str:
    """Verify SRI sha512 integrity, else the legacy shasum; report which one was used.

    A mismatch is ``DIGEST_MISMATCH`` (SPEC §6.5) and stops the run. No digest at all is
    an error too: trusting unverified bytes would defeat TB2.
    """
    expected = expected_digest(dist)
    if not digest_matches(data, expected):
        raise FetchError(FetchErrorCode.DIGEST_MISMATCH)
    return expected.method


def fetch_pair(
    *,
    name: str,
    old_version: str,
    new_version: str,
    config: Config,
    client: HttpClient,
    workdir: Path,
    cache: DownloadCache | None = None,
) -> FetchPair:
    """Fetch the SPEC §3 document once, then both tarballs to temp files."""
    validate_name(name)
    validate_version(old_version)
    validate_version(new_version)

    document, versions = _document_versions(client, name, config)

    old = _artifact(
        version=old_version,
        filename="old.tgz",
        document=document,
        versions=versions,
        config=config,
        client=client,
        workdir=workdir,
        cache=cache,
    )
    new = _artifact(
        version=new_version,
        filename="new.tgz",
        document=document,
        versions=versions,
        config=config,
        client=client,
        workdir=workdir,
        cache=cache,
    )
    return FetchPair(name=name, old=old, new=new)


def fetch_release(
    *,
    name: str,
    version: str,
    config: Config,
    client: HttpClient,
    workdir: Path,
    cache: DownloadCache | None = None,
) -> VersionArtifact:
    """Fetch one exact version for a package with no predecessor: same document, same checks."""
    validate_name(name)
    validate_version(version)
    document, versions = _document_versions(client, name, config)
    return _artifact(
        version=version,
        filename="new.tgz",
        document=document,
        versions=versions,
        config=config,
        client=client,
        workdir=workdir,
        cache=cache,
    )


def _document_versions(
    client: HttpClient, name: str, config: Config
) -> tuple[dict[str, Any], Mapping[str, Any]]:
    document = _document(client, name, config)
    versions = document.get("versions")
    if not isinstance(versions, dict):
        raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID)
    declared = document.get("name")
    if isinstance(declared, str) and declared.casefold() != name.casefold():
        raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID)
    return document, versions


def _document(client: HttpClient, name: str, config: Config) -> dict[str, Any]:
    body = _fetch_bytes(
        client,
        build_doc_url(name),
        cap=config.fetch.max_metadata_bytes,
        config=config,
    )
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID) from None
    if not isinstance(parsed, dict):
        raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID)
    return cast(dict[str, Any], parsed)


def _artifact(
    *,
    version: str,
    filename: str,
    document: Mapping[str, Any],
    versions: Mapping[str, Any],
    config: Config,
    client: HttpClient,
    workdir: Path,
    cache: DownloadCache | None,
) -> VersionArtifact:
    entry = versions.get(version)
    if not isinstance(entry, dict):
        raise FetchError(FetchErrorCode.VERSION_NOT_FOUND)
    dist = entry.get("dist")
    if not isinstance(dist, dict):
        raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID)
    url = dist.get("tarball")
    if not isinstance(url, str) or not is_registry_url(url):
        raise FetchError(FetchErrorCode.TARBALL_URL_INVALID)

    expected = expected_digest(dist)
    path = workdir / filename
    if cache is not None:
        cached = cache.get(expected)
        if cached is not None:
            path.write_bytes(cached)
            return VersionArtifact(
                version=version,
                path=path,
                digest_method=expected.method,
                size=len(cached),
                metadata=_metadata_for(entry),
                published_at=_published_at(document, version),
            )

    body = _fetch_bytes(
        client,
        url,
        cap=config.fetch.max_tarball_bytes,
        config=config,
    )
    path.write_bytes(body)
    # Verify the bytes that actually landed in the temp file, not the response object.
    digest_method = verify_digest(path.read_bytes(), dist)
    if cache is not None:
        cache.put(expected, body)
    return VersionArtifact(
        version=version,
        path=path,
        digest_method=digest_method,
        size=len(body),
        metadata=_metadata_for(entry),
        published_at=_published_at(document, version),
    )


def _fetch_bytes(client: HttpClient, url: str, *, cap: int, config: Config) -> bytes:
    """One logical GET, following redirects only while they stay on the registry host."""
    current = url
    for _ in range(config.fetch.max_redirects + 1):
        if not is_registry_url(current):
            raise FetchError(FetchErrorCode.REDIRECT_REJECTED)
        response = client.get(
            current,
            user_agent=config.fetch.user_agent,
            timeout=config.fetch.request_timeout_seconds,
            max_bytes=cap + 1,
        )
        if response.status not in REDIRECT_STATUSES:
            if response.status != 200:
                raise FetchError(FetchErrorCode.HTTP_ERROR)
            if len(response.body) > cap:
                raise FetchError(FetchErrorCode.SIZE_LIMIT_EXCEEDED)
            return response.body
        location = _header(response.headers, "location")
        if location is None:
            raise FetchError(FetchErrorCode.REDIRECT_REJECTED)
        current = urllib.parse.urljoin(current, location)
    raise FetchError(FetchErrorCode.REDIRECT_REJECTED)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    return next(
        (value for key, value in headers.items() if key.casefold() == name.casefold()),
        None,
    )


def _metadata_for(entry: Mapping[str, Any]) -> dict[str, Any]:
    return {key: entry[key] for key in _CONSUMED_VERSION_FIELDS if key in entry}


def declared_unpacked_size(metadata: Mapping[str, Any]) -> object:
    """The registry's optional ``dist.unpackedSize`` for the TB3 cross-check, or None."""
    dist = metadata.get("dist")
    return dist.get("unpackedSize") if isinstance(dist, dict) else None


def _published_at(document: Mapping[str, Any], version: str) -> datetime:
    """SPEC §3's ``time`` map is the only source of a publish instant."""
    times = document.get("time")
    if isinstance(times, dict):
        raw = times.get(version)
        if isinstance(raw, str):
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
            if parsed is not None:
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=UTC)
                return parsed
    return UNKNOWN_PUBLISHED_AT
