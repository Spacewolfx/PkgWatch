"""Registry downloaders: the only place besides ``ingest/`` with network egress.

v0.1 ships one source, :mod:`pkgwatch.fetch.npm`. It reads the SPEC §3 npm document
endpoint and the tarball URL that document advertises, verifies the digest, and writes
the artifact to a temp file. Extraction belongs to ``pkgwatch.sandbox``, never here.
"""

from pkgwatch.fetch.npm import (
    FetchError,
    FetchErrorCode,
    FetchPair,
    FetchTimeout,
    HttpClient,
    HttpResponse,
    UrllibClient,
    VersionArtifact,
    build_doc_url,
    expected_digest,
    fetch_pair,
    fetch_release,
    is_registry_url,
    parse_spec,
    validate_name,
    validate_version,
    verify_digest,
)

__all__ = [
    "FetchError",
    "FetchErrorCode",
    "FetchPair",
    "FetchTimeout",
    "HttpClient",
    "HttpResponse",
    "UrllibClient",
    "VersionArtifact",
    "build_doc_url",
    "expected_digest",
    "fetch_pair",
    "fetch_release",
    "is_registry_url",
    "parse_spec",
    "validate_name",
    "validate_version",
    "verify_digest",
]
