"""Offline npm registry stand-in for the v0.1 compare tests.

Tarballs are built from the committed, synthetic fixture trees. The SPEC §3 package
document and its advertised ``dist.tarball`` URLs are served through an injected HTTP
client: no sockets, no live registry, and no package content is ever run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pkgwatch.fetch.npm import HttpResponse, build_doc_url
from tests.support.archives import Entry, make_tar
from tests.support.fixtures import PACKAGE_FIXTURES

OLD_VERSION = "1.0.0"
NEW_VERSION = "1.1.0"
REGISTRY_HOST = "registry.npmjs.org"
PUBLISHED_OLD = "2026-11-01T12:00:00.000Z"
PUBLISHED_NEW = "2026-11-05T12:00:00.000Z"


def tree_entries(case_name: str, side: str) -> list[Entry]:
    """The same npm tarball layout as ``tests.support.fixtures.context_from_case``."""
    root = PACKAGE_FIXTURES / case_name / side
    if not root.is_dir():
        raise AssertionError(f"missing fixture tree: {root}")
    return [
        Entry(f"package/{path.relative_to(root).as_posix()}", path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def tarball_bytes(tmp_path: Path, case_name: str, side: str, *, escape: bool = False) -> bytes:
    """A synthetic .tgz; ``escape`` adds one traversal member for sandbox tests."""
    entries = tree_entries(case_name, side)
    if escape:
        entries.append(Entry("../escape.js", b"// synthetic traversal probe\n"))
    archive = make_tar(tmp_path / f"{case_name}-{side}.tgz", entries)
    return archive.read_bytes()


def tarball_from_files(tmp_path: Path, name: str, files: Mapping[str, bytes]) -> bytes:
    """A synthetic package tarball from an explicit virtual-path -> bytes map."""
    entries = [Entry(f"package/{path}", data) for path, data in sorted(files.items())]
    return make_tar(tmp_path / f"{name}.tgz", entries).read_bytes()


def dist_for(payload: bytes, *, method: str = "integrity", corrupt: bool = False) -> dict[str, str]:
    """A registry ``dist`` block with a real SRI/SHA-1 digest, or a deliberately wrong one."""
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
    shasum = hashlib.sha1(payload).hexdigest()  # noqa: S324 - npm's legacy dist.shasum
    if corrupt:
        integrity = "sha512-" + base64.b64encode(b"deliberately-wrong").decode("ascii")
        shasum = "0" * 40
    if method == "none":
        return {}
    if method == "shasum":
        return {"shasum": shasum}
    return {"integrity": integrity, "shasum": shasum}


def _ok(payload: bytes, max_bytes: int) -> HttpResponse:
    return HttpResponse(
        status=200,
        headers={"content-type": "application/octet-stream"},
        body=payload[:max_bytes],
    )


@dataclass
class FakeRegistry:
    """Serves one package document and two tarballs; records every request."""

    name: str = "demo-pkg"
    old_version: str = OLD_VERSION
    new_version: str = NEW_VERSION
    old_tarball: bytes = b""
    new_tarball: bytes = b""
    old_dist: dict[str, str] = field(default_factory=dict)
    new_dist: dict[str, str] = field(default_factory=dict)
    redirects: dict[str, str] = field(default_factory=dict)
    aliases: dict[str, bytes] = field(default_factory=dict)
    doc_override: bytes | None = None
    requests: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    timeouts: list[float] = field(default_factory=list)

    @property
    def doc_url(self) -> str:
        return build_doc_url(self.name)

    @property
    def old_url(self) -> str:
        return self._tarball_url(self.old_version)

    @property
    def new_url(self) -> str:
        return self._tarball_url(self.new_version)

    def _tarball_url(self, version: str) -> str:
        encoded = urllib.parse.quote(self.name, safe="@")
        leaf = self.name.split("/")[-1]
        return f"https://{REGISTRY_HOST}/{encoded}/-/{leaf}-{version}.tgz"

    def set_new(self, payload: bytes, *, method: str = "integrity") -> None:
        """Replace the new tarball and keep its advertised digest consistent."""
        self.new_tarball = payload
        self.new_dist = dist_for(payload, method=method)

    def document(self) -> dict[str, Any]:
        """Only SPEC §3 fields; no install scripts, so the metadata rule stays quiet."""
        return {
            "name": self.name,
            "dist-tags": {"latest": self.new_version},
            "time": {
                "created": PUBLISHED_OLD,
                "modified": PUBLISHED_NEW,
                self.old_version: PUBLISHED_OLD,
                self.new_version: PUBLISHED_NEW,
            },
            "versions": {
                self.old_version: {
                    "name": self.name,
                    "version": self.old_version,
                    "scripts": {"test": "echo run tests"},
                    "dist": {"tarball": self.old_url, **self.old_dist},
                },
                self.new_version: {
                    "name": self.name,
                    "version": self.new_version,
                    "scripts": {"test": "echo run tests"},
                    "dist": {"tarball": self.new_url, **self.new_dist},
                },
            },
        }

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        self.requests.append(url)
        self.user_agents.append(user_agent)
        self.timeouts.append(timeout)
        if url in self.redirects:
            return HttpResponse(
                status=302,
                headers={"Location": self.redirects[url]},
                body=b"",
            )
        if url in self.aliases:
            return _ok(self.aliases[url], max_bytes)
        if url == self.doc_url:
            if self.doc_override is None:
                return _ok(json.dumps(self.document()).encode("utf-8"), max_bytes)
            return _ok(self.doc_override, max_bytes)
        if url == self.old_url:
            return _ok(self.old_tarball, max_bytes)
        if url == self.new_url:
            return _ok(self.new_tarball, max_bytes)
        return HttpResponse(status=404, headers={}, body=b"")


def make_registry(tmp_path: Path, case_name: str, *, name: str = "demo-pkg") -> FakeRegistry:
    old = tarball_bytes(tmp_path, case_name, "old")
    new = tarball_bytes(tmp_path, case_name, "new")
    return FakeRegistry(
        name=name,
        old_tarball=old,
        new_tarball=new,
        old_dist=dist_for(old),
        new_dist=dist_for(new),
    )


def package_registry(
    tmp_path: Path,
    name: str,
    *,
    old_version: str,
    new_version: str,
    old_files: Mapping[str, bytes],
    new_files: Mapping[str, bytes],
) -> FakeRegistry:
    """One package's two versions, with digests consistent with the tarball bytes."""
    safe = name.replace("/", "-")
    old = tarball_from_files(tmp_path, f"{safe}-{old_version}", old_files)
    new = tarball_from_files(tmp_path, f"{safe}-{new_version}", new_files)
    return FakeRegistry(
        name=name,
        old_version=old_version,
        new_version=new_version,
        old_tarball=old,
        new_tarball=new,
        old_dist=dist_for(old),
        new_dist=dist_for(new),
    )


def case_registry(tmp_path: Path, case_name: str, *, name: str = "demo-pkg") -> FakeRegistry:
    """A committed fixture tree served at the versions a lockfile pair uses."""
    return package_registry(
        tmp_path,
        name,
        old_version=OLD_VERSION,
        new_version=NEW_VERSION,
        old_files=_tree_files(case_name, "old"),
        new_files=_tree_files(case_name, "new"),
    )


def resolved_url(registry: FakeRegistry, version: str) -> str:
    """The exact ``resolved`` URL this registry advertises, so a lockfile matches it."""
    if version == registry.old_version:
        return registry.old_url
    if version == registry.new_version:
        return registry.new_url
    raise AssertionError(f"version not served by this registry: {version}")


def _tree_files(case_name: str, side: str) -> dict[str, bytes]:
    root = PACKAGE_FIXTURES / case_name / side
    if not root.is_dir():
        raise AssertionError(f"missing fixture tree: {root}")
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class MultiRegistry:
    """Several packages behind one injected client, safe for concurrent pair analysis.

    ``FakeRegistry`` serves a single package, while a lock run analyses many pairs at once
    (``[lock].concurrency``), so dispatch is by exact URL and request logging is guarded.
    """

    def __init__(self, packages: Iterable[FakeRegistry] = ()) -> None:
        self._packages = {item.name: item for item in packages}
        self._lock = threading.Lock()
        self.requests: list[str] = []

    def add(self, registry: FakeRegistry) -> FakeRegistry:
        self._packages[registry.name] = registry
        return registry

    def registry(self, name: str) -> FakeRegistry:
        return self._packages[name]

    def get(self, url: str, *, user_agent: str, timeout: float, max_bytes: int) -> HttpResponse:
        with self._lock:
            self.requests.append(url)
        owner = self._owner(url)
        if owner is None:
            return HttpResponse(status=404, headers={}, body=b"")
        return owner.get(url, user_agent=user_agent, timeout=timeout, max_bytes=max_bytes)

    def _owner(self, url: str) -> FakeRegistry | None:
        for item in self._packages.values():
            if url in (item.doc_url, item.old_url, item.new_url):
                return item
        return None
