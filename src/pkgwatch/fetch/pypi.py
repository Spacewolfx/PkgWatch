"""PyPI metadata and artifact fetching for the ``compare`` command.

The only URL constructed here is the operator-approved document endpoint
``GET https://pypi.org/pypi/{name}/json``. Artifact URLs are read from that
document's ``releases[v]`` file entries; they are never invented. Both URLs, and
every redirect hop, are restricted to HTTPS on the PyPI host allow-list
(``pypi.org`` for the document, ``files.pythonhosted.org`` for artifacts).

Names go through PEP 503 normalisation before a URL is built, so ``Foo_Bar``,
``foo-bar`` and ``foo.bar`` address the same project; the original spelling is
what the report shows. Artifact bytes are hostile input: written to a temp file,
verified against the registry digest, and handed to ``pkgwatch.sandbox``. Nothing
here decompresses, parses as source, or runs package content.
"""

from __future__ import annotations

import json
import posixpath
import re
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pkgwatch.config import Config
from pkgwatch.fetch.cache import DownloadCache, ExpectedDigest, digest_matches
from pkgwatch.fetch.npm import (
    REDIRECT_STATUSES,
    UNKNOWN_PUBLISHED_AT,
    FetchError,
    FetchErrorCode,
    FetchPair,
    HttpClient,
    VersionArtifact,
)
from pkgwatch.models import Ecosystem
from pkgwatch.version import UnsupportedVersion
from pkgwatch.version import parse as parse_version

PYPI_DOC_URL_TEMPLATE = "https://pypi.org/pypi/{name}/json"
PYPI_VERSION_DOC_URL_TEMPLATE = "https://pypi.org/pypi/{name}/{version}/json"
PYPI_ALLOWED_HOSTS = frozenset({"pypi.org", "files.pythonhosted.org"})

# Info fields of a per-version document that pypi_metadata_changes diffs (SPEC §9.2).
_METADATA_INFO_FIELDS = (
    "requires_dist",
    "requires_python",
    "classifiers",
    "project_urls",
    "entry_points",
    "summary",
)

_SPEC_PREFIX = "pypi:"
MAX_NAME_LENGTH = 214
MAX_VERSION_LENGTH = 128

# PEP 503 shape: ASCII alphanumerics with inner . _ - separators. Leading/trailing
# separators, path pieces, control characters and non-ASCII are rejected before any
# URL interpolation sees the name.
_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_NORMALIZE_RE = re.compile(r"[-_.]+")

_DIGEST_HEX_LENGTHS = {"sha256": 64, "blake2b_256": 64}


def normalize_name(name: str) -> str:
    """PEP 503: runs of ``-_.`` collapse to one ``-``, everything lowercases."""
    return _NORMALIZE_RE.sub("-", name).lower()


def validate_name_pypi(name: str) -> None:
    """Reject anything that is not a plain PyPI project name, before a URL is built."""
    if not name or len(name) > MAX_NAME_LENGTH or not _NAME_RE.fullmatch(name) or ".." in name:
        raise FetchError(FetchErrorCode.INVALID_PACKAGE_NAME)


def validate_version_pypi(version: str) -> None:
    """Exact PEP 440 versions only, via the SPEC §6.4 parser."""
    if not version or len(version) > MAX_VERSION_LENGTH:
        raise FetchError(FetchErrorCode.INVALID_VERSION)
    try:
        parse_version(Ecosystem.PYPI, version)
    except UnsupportedVersion:
        raise FetchError(FetchErrorCode.INVALID_VERSION) from None


def parse_spec(text: str) -> tuple[str, str]:
    """Split ``pypi:<name>@<version>``; anything else stays an ``INVALID_SPEC``."""
    if not text.startswith(_SPEC_PREFIX):
        raise FetchError(FetchErrorCode.INVALID_SPEC)
    body = text[len(_SPEC_PREFIX) :]
    separator = body.rfind("@")
    if separator <= 0 or separator == len(body) - 1:
        raise FetchError(FetchErrorCode.INVALID_SPEC)
    name = body[:separator]
    version = body[separator + 1 :]
    validate_name_pypi(name)
    validate_version_pypi(version)
    return name, version


def build_doc_url(name: str) -> str:
    """The only URL pkgwatch constructs for PyPI; validation happens first.

    The normalized name is ``[a-z0-9-]``-only, so no quoting is needed.
    """
    validate_name_pypi(name)
    return PYPI_DOC_URL_TEMPLATE.format(name=normalize_name(name))


def build_version_doc_url(name: str, version: str) -> str:
    """The per-version document: PEP 503 name, the exact validated version string."""
    validate_name_pypi(name)
    validate_version_pypi(version)
    return PYPI_VERSION_DOC_URL_TEMPLATE.format(name=normalize_name(name), version=version)


def is_pypi_url(url: str) -> bool:
    """HTTPS on the allow-list only: no userinfo, no alternative port, no plain HTTP."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return False
    return (
        parts.scheme == "https"
        and parts.hostname in PYPI_ALLOWED_HOSTS
        and port in (None, 443)
        and parts.username is None
        and parts.password is None
    )


def expected_digest_pypi(file_entry: Mapping[str, Any]) -> ExpectedDigest:
    """``digests.sha256`` first, ``digests.blake2b_256`` as the fallback.

    A malformed hex value counts as absent; other algorithms (md5) alone mean the
    entry cannot be verified, which is an error rather than a silent pass.
    """
    digests = file_entry.get("digests")
    if not isinstance(digests, dict):
        raise FetchError(FetchErrorCode.DIGEST_MISSING)
    for algorithm in ("sha256", "blake2b_256"):
        raw = digests.get(algorithm)
        if not isinstance(raw, str):
            continue
        value = raw.strip().lower()
        if len(value) != _DIGEST_HEX_LENGTHS[algorithm] or any(
            char not in "0123456789abcdef" for char in value
        ):
            continue
        return ExpectedDigest(method=f"digests.{algorithm}", algorithm=algorithm, hexdigest=value)
    if digests:
        raise FetchError(FetchErrorCode.DIGEST_UNSUPPORTED)
    raise FetchError(FetchErrorCode.DIGEST_MISSING)


def fetch_pair_pypi(
    *,
    name: str,
    old_version: str,
    new_version: str,
    config: Config,
    client: HttpClient,
    workdir: Path,
    cache: DownloadCache | None = None,
) -> FetchPair:
    """Fetch the document once, then both artifacts to temp files."""
    validate_name_pypi(name)
    validate_version_pypi(old_version)
    validate_version_pypi(new_version)

    releases = _document_releases(client, name, config)
    old = _artifact(
        version=old_version,
        slot="old",
        releases=releases,
        config=config,
        client=client,
        workdir=workdir,
        cache=cache,
    )
    new = _artifact(
        version=new_version,
        slot="new",
        releases=releases,
        config=config,
        client=client,
        workdir=workdir,
        cache=cache,
    )
    old = replace(old, metadata=_version_metadata(client, name, old_version, config))
    new = replace(new, metadata=_version_metadata(client, name, new_version, config))
    return FetchPair(name=name, old=old, new=new)


def fetch_release_pypi(
    *,
    name: str,
    version: str,
    config: Config,
    client: HttpClient,
    workdir: Path,
    cache: DownloadCache | None = None,
) -> VersionArtifact:
    """Fetch one exact PyPI version: same document, same checks."""
    validate_name_pypi(name)
    validate_version_pypi(version)
    releases = _document_releases(client, name, config)
    return _artifact(
        version=version,
        slot="new",
        releases=releases,
        config=config,
        client=client,
        workdir=workdir,
        cache=cache,
    )


def _document_releases(client: HttpClient, name: str, config: Config) -> Mapping[str, Any]:
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
    document = cast(dict[str, Any], parsed)
    releases = document.get("releases")
    if not isinstance(releases, dict):
        raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID)
    info = document.get("info")
    if isinstance(info, dict):
        declared = info.get("name")
        if isinstance(declared, str) and normalize_name(declared) != normalize_name(name):
            raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID)
    return cast(Mapping[str, Any], releases)


def _version_metadata(
    client: HttpClient, name: str, version: str, config: Config
) -> dict[str, Any]:
    """Metadata fields of one exact version, or ``{}`` when unavailable.

    A version document that cannot be fetched or parsed degrades to ``{}`` (every
    ``pypi_metadata_changes`` field reads as absent) rather than failing the compare,
    so metadata is best-effort and an offline run still analyses the artifacts.
    """
    try:
        body = _fetch_bytes(
            client,
            build_version_doc_url(name, version),
            cap=config.fetch.max_metadata_bytes,
            config=config,
        )
    except FetchError:
        return {}
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    metadata: dict[str, Any] = {}
    info = parsed.get("info")
    if isinstance(info, dict):
        for field in _METADATA_INFO_FIELDS:
            if field in info:
                metadata[field] = info[field]
    urls = parsed.get("urls")
    if isinstance(urls, list):
        reported = [
            entry.get("yanked") for entry in urls if isinstance(entry, dict) and "yanked" in entry
        ]
        if reported:
            metadata["yanked"] = any(value is True for value in reported)
    return metadata


def _select_file(files: Sequence[Any]) -> Mapping[str, Any]:
    """sdist first, then wheel, each in filename order; deterministic, no fall-through."""

    def by_filename(entry: Mapping[str, Any]) -> str:
        filename = entry.get("filename")
        return filename if isinstance(filename, str) else ""

    entries = [cast(Mapping[str, Any], item) for item in files if isinstance(item, dict)]
    sdists = sorted(
        (item for item in entries if item.get("packagetype") == "sdist"), key=by_filename
    )
    if sdists:
        return sdists[0]
    wheels = sorted(
        (
            item
            for item in entries
            if item.get("packagetype") == "bdist_wheel" or by_filename(item).endswith(".whl")
        ),
        key=by_filename,
    )
    if wheels:
        return wheels[0]
    raise FetchError(FetchErrorCode.ARTIFACT_UNAVAILABLE)


def _filename_leaf(file_entry: Mapping[str, Any], url: str) -> str:
    """A safe single-segment filename so the artifact keeps its .tar.gz/.whl suffix."""
    candidate = file_entry.get("filename")
    if not isinstance(candidate, str) or not candidate:
        candidate = posixpath.basename(urllib.parse.urlsplit(url).path)
    if (
        not candidate
        or candidate in {".", ".."}
        or "/" in candidate
        or "\\" in candidate
        or "\x00" in candidate
    ):
        raise FetchError(FetchErrorCode.REGISTRY_DOC_INVALID)
    return candidate


def _artifact(
    *,
    version: str,
    slot: str,
    releases: Mapping[str, Any],
    config: Config,
    client: HttpClient,
    workdir: Path,
    cache: DownloadCache | None,
) -> VersionArtifact:
    files = releases.get(version)
    if not isinstance(files, list):
        raise FetchError(FetchErrorCode.VERSION_NOT_FOUND)
    file_entry = _select_file(files)
    url = file_entry.get("url")
    if not isinstance(url, str) or not is_pypi_url(url):
        raise FetchError(FetchErrorCode.TARBALL_URL_INVALID)

    expected = expected_digest_pypi(file_entry)
    filename = _filename_leaf(file_entry, url)
    path = workdir / f"{slot}-{filename}"
    if cache is not None:
        cached = cache.get(expected)
        if cached is not None:
            path.write_bytes(cached)
            return VersionArtifact(
                version=version,
                path=path,
                digest_method=expected.algorithm,
                size=len(cached),
                metadata={},
                published_at=_published_at(file_entry),
            )

    body = _fetch_bytes(
        client,
        url,
        cap=config.fetch.max_tarball_bytes,
        config=config,
    )
    path.write_bytes(body)
    # Verify the bytes that actually landed in the temp file, not the response object.
    if not digest_matches(path.read_bytes(), expected):
        raise FetchError(FetchErrorCode.DIGEST_MISMATCH)
    if cache is not None:
        cache.put(expected, body)
    return VersionArtifact(
        version=version,
        path=path,
        digest_method=expected.algorithm,
        size=len(body),
        metadata={},
        published_at=_published_at(file_entry),
    )


def _published_at(file_entry: Mapping[str, Any]) -> datetime:
    """The file entry's upload instant; a missing or malformed one stays unknown."""
    for field in ("upload_time_iso_8601", "upload_time"):
        raw = file_entry.get(field)
        if not isinstance(raw, str):
            continue
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed
    return UNKNOWN_PUBLISHED_AT


def _fetch_bytes(client: HttpClient, url: str, *, cap: int, config: Config) -> bytes:
    """One logical GET, following redirects only while they stay on the allow-list."""
    current = url
    for _ in range(config.fetch.max_redirects + 1):
        if not is_pypi_url(current):
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
        location = next(
            (value for key, value in response.headers.items() if key.casefold() == "location"),
            None,
        )
        if location is None:
            raise FetchError(FetchErrorCode.REDIRECT_REJECTED)
        current = urllib.parse.urljoin(current, location)
    raise FetchError(FetchErrorCode.REDIRECT_REJECTED)
