"""Offline PyPI stand-in for the compare tests.

Serves the PyPI JSON API document shape (``info`` + ``releases`` with per-file
entries) and artifact bytes on ``files.pythonhosted.org`` through an injected HTTP
client: no sockets, no live registry, and no package content is ever run. Sdist and
wheel payloads are built from caller-supplied file maps, never from real packages.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pkgwatch.fetch.npm import HttpResponse
from pkgwatch.fetch.pypi import build_doc_url, normalize_name
from tests.support.archives import Entry, make_tar, make_zip

PYPI_HOST = "pypi.org"
FILES_HOST = "files.pythonhosted.org"
PUBLISHED_OLD = "2026-11-01T12:00:00.000000Z"
PUBLISHED_NEW = "2026-11-05T12:00:00.000000Z"


def metadata_text(name: str, version: str, *, requires: tuple[str, ...] = ()) -> str:
    """A minimal PEP 566 metadata document: what PKG-INFO and METADATA both carry."""
    lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    lines.extend(f"Requires-Dist: {item}" for item in requires)
    return "\n".join(lines) + "\n"


def sdist_bytes(
    tmp_path: Path,
    name: str,
    version: str,
    files: Mapping[str, bytes],
    *,
    requires: tuple[str, ...] = (),
) -> bytes:
    """A synthetic .tar.gz rooted at ``<normalized>-<version>/``, with a PKG-INFO."""
    root = f"{normalize_name(name)}-{version}"
    entries = [Entry(f"{root}/PKG-INFO", metadata_text(name, version, requires=requires).encode())]
    entries.extend(Entry(f"{root}/{path}", data) for path, data in sorted(files.items()))
    return make_tar(tmp_path / f"{root}.tar.gz", entries).read_bytes()


def wheel_bytes(
    tmp_path: Path,
    name: str,
    version: str,
    files: Mapping[str, bytes],
    *,
    requires: tuple[str, ...] = (),
) -> bytes:
    """A synthetic .whl (zip) with a ``<normalized>-<version>.dist-info/METADATA``."""
    dist = f"{normalize_name(name).replace('-', '_')}-{version}.dist-info"
    entries = [Entry(f"{dist}/METADATA", metadata_text(name, version, requires=requires).encode())]
    entries.extend(Entry(path, data) for path, data in sorted(files.items()))
    return make_zip(tmp_path / f"{dist}.whl", entries).read_bytes()


def default_filename(name: str, version: str, packagetype: str) -> str:
    normalized = normalize_name(name)
    if packagetype == "sdist":
        return f"{normalized}-{version}.tar.gz"
    return f"{normalized.replace('-', '_')}-{version}-py3-none-any.whl"


def _digests_for(payload: bytes, digest: str) -> dict[str, str]:
    sha256 = hashlib.sha256(payload).hexdigest()
    blake2b = hashlib.blake2b(payload, digest_size=32).hexdigest()
    if digest == "sha256":
        return {"sha256": sha256, "blake2b_256": blake2b}
    if digest == "blake2b_256":
        return {"blake2b_256": blake2b}
    if digest == "md5":
        return {"md5": hashlib.md5(payload).hexdigest()}  # noqa: S324 - PyPI still lists md5
    if digest == "none":
        return {}
    if digest == "corrupt":
        return {"sha256": "0" * 64}
    raise AssertionError(f"unknown digest mode: {digest}")


def _ok(payload: bytes, max_bytes: int) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={"content-type": "application/octet-stream"},
        body=payload[:max_bytes],
    )


@dataclass
class PyPIRegistry:
    """Serves one project document and its release artifacts; records every request."""

    name: str = "demo-pkg"
    releases: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    artifacts: dict[str, bytes] = field(default_factory=dict)
    doc_override: bytes | None = None
    version_info: dict[str, dict[str, Any]] = field(default_factory=dict)
    redirects: dict[str, str] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)

    @property
    def doc_url(self) -> str:
        return build_doc_url(self.name)

    def version_doc_url(self, version: str) -> str:
        return f"https://{PYPI_HOST}/pypi/{normalize_name(self.name)}/{version}/json"

    def artifact_url(self, filename: str) -> str:
        return f"https://{FILES_HOST}/packages/aa/bb/{filename}"

    def add_release(
        self,
        version: str,
        payload: bytes,
        *,
        packagetype: str = "sdist",
        digest: str = "sha256",
        filename: str | None = None,
        url: str | None = None,
        published: str = PUBLISHED_NEW,
    ) -> str:
        """Register one file entry for a version; returns the URL it is served at."""
        name = filename or default_filename(self.name, version, packagetype)
        target = url or self.artifact_url(name)
        self.releases.setdefault(version, []).append(
            {
                "filename": name,
                "url": target,
                "packagetype": packagetype,
                "digests": _digests_for(payload, digest),
                "upload_time_iso_8601": published,
            }
        )
        self.artifacts[target] = payload
        return target

    def document(self) -> dict[str, Any]:
        return {
            "info": {"name": self.name, "version": max(self.releases, default="0")},
            "releases": {version: list(entries) for version, entries in self.releases.items()},
        }

    def version_document(self, version: str) -> dict[str, Any]:
        info = {"name": self.name, "version": version, **self.version_info.get(version, {})}
        return {"info": info, "urls": list(self.releases.get(version, []))}

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        self.requests.append(url)
        self.user_agents.append(user_agent)
        if url in self.redirects:
            return HttpResponse(
                status=302,
                headers={"Location": self.redirects[url]},
                body=b"",
            )
        if url == self.doc_url:
            body = json.dumps(self.document()).encode("utf-8")
            return _ok(self.doc_override if self.doc_override is not None else body, max_bytes)
        for version in self.releases:
            if url == self.version_doc_url(version):
                body = json.dumps(self.version_document(version)).encode("utf-8")
                return _ok(body, max_bytes)
        if url in self.artifacts:
            return _ok(self.artifacts[url], max_bytes)
        return HttpResponse(status=404, headers={}, body=b"")


def pypi_pair_registry(
    tmp_path: Path,
    name: str,
    *,
    old_version: str,
    new_version: str,
    old_files: Mapping[str, bytes],
    new_files: Mapping[str, bytes],
    old_packagetype: str = "sdist",
    new_packagetype: str = "sdist",
    old_requires: tuple[str, ...] = (),
    new_requires: tuple[str, ...] = (),
) -> PyPIRegistry:
    """Two versions of one project, digests consistent with the artifact bytes."""
    registry = PyPIRegistry(name=name)
    builders = {"sdist": sdist_bytes, "bdist_wheel": wheel_bytes}
    old_payload = builders[old_packagetype](
        tmp_path, name, old_version, old_files, requires=old_requires
    )
    new_payload = builders[new_packagetype](
        tmp_path, name, new_version, new_files, requires=new_requires
    )
    registry.add_release(
        old_version, old_payload, packagetype=old_packagetype, published=PUBLISHED_OLD
    )
    registry.add_release(new_version, new_payload, packagetype=new_packagetype)
    if old_requires:
        registry.version_info[old_version] = {"requires_dist": list(old_requires)}
    if new_requires:
        registry.version_info[new_version] = {"requires_dist": list(new_requires)}
    return registry
