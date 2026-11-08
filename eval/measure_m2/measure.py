"""One-off measurement of the M2 family 1 and 2 npm rules.

Not part of pkgwatch: nothing under ``src/`` may import this file. It answers one
question -- do the shipped rules separate known-malicious release pairs from benign
ones -- using only the product's own sandbox, diff, rules and score modules. No
package code is executed, installed, imported or built, and nothing is decompressed
outside ``pkgwatch.sandbox``.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import random
import re
import shutil
import statistics
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pkgwatch.config import Config, PathsConfig
from pkgwatch.diff import build_diff_context
from pkgwatch.models import DiffContext, Ecosystem, ExtractionResult, Finding, ScoreResult
from pkgwatch.rules import RULES, families_by_rule_id, rule_set_version
from pkgwatch.rules.family1_lifecycle import INSTALL_SCRIPT_KEYS
from pkgwatch.rules.runner import analysis_incomplete, run_rules
from pkgwatch.sandbox import ArchiveRejected, extract_archive
from pkgwatch.score.engine import score

# SPEC §3, probed 2026-11-05. Nothing else is contacted, and tarball URLs are read from the
# document this endpoint returns rather than constructed here.
NPM_DOC_URL = "https://registry.npmjs.org/{name}"
NPM_REGISTRY_HOST = "registry.npmjs.org"
USER_AGENT = "pkgwatch-m2-eval (one-off static measurement run; no contact address configured)"
DOC_TIMEOUT_SECONDS = 60

SAFE_NAME_RE = re.compile(r"^(?:@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|[A-Za-z0-9._-]+)$")
SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9._+-]+$")
RETRIEVED_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
APACHE_MARKER = "apache license"
REGISTRY_TIME_KEYS = ("created", "modified")

# A backstop against a runaway walk. The structural check below catches the real mistake; this
# only fires if a directory that *looks* like the clone turns out to hold millions of files.
ADVISORY_FILE_LIMIT = 200_000

STRATUM_MALICIOUS = "malicious"
STRATUM_BENIGN_INSTALL = "benign_with_install_script"
STRATUM_BENIGN_PLAIN = "benign_without_install_script"

# Skip and exclusion reasons. Stable strings: they are the audit trail in run.json.
SKIP_UNSAFE_NAME = "UNSAFE_PACKAGE_NAME"
SKIP_DOC_UNAVAILABLE = "REGISTRY_DOC_UNAVAILABLE"
SKIP_NAME_NOT_IN_DOC = "PACKAGE_NAME_NOT_IN_DOC"
SKIP_NO_PREDECESSOR = "NO_PREDECESSOR"
SKIP_AMBIGUOUS_PREDECESSOR = "AMBIGUOUS_PREDECESSOR"
SKIP_VERSION_NOT_IN_DOC = "AFFECTED_VERSION_NOT_IN_DOC"
SKIP_OVERLAP = "EXCLUDED_OVERLAP_WITH_MALICIOUS"
SKIP_TARBALL_URL = "TARBALL_URL_MISSING"
ARTIFACT_NOT_CACHED = "ARTIFACT_NOT_CACHED_OFFLINE"
XCLUDE_DIGEST = "DIGEST_MISMATCH"
XCLUDE_OFFSITE = "OFFSITE_TARBALL_URL"
XCLUDE_REJECTED = "SANDBOX_REJECTED"
XCLUDE_INCOMPLETE = "ANALYSIS_INCOMPLETE"
XCLUDE_FETCH_FAILED = "TARBALL_FETCH_FAILED"
XCLUDE_NO_DIGEST = "DIST_DIGEST_ABSENT_FROM_DOC"


class MeasureError(Exception):
    """A missing or contradictory input. Never worked around silently."""


@dataclass(frozen=True)
class Inputs:
    ossf_dir: Path
    benign_list: Path
    seed: int
    max_pairs: int
    out_dir: Path
    config_path: Path | None
    offline: bool
    refresh_docs: bool
    sleep_seconds: float
    keep_extracted: bool
    limit: int | None
    tarball_hosts: tuple[str, ...]
    with_evidence: Path | None
    ossf_commit: str | None


@dataclass(frozen=True)
class Candidate:
    package: str
    old_version: str
    new_version: str
    published_at: str
    stratum: str
    origin: str

    def key(self) -> tuple[str, str, str]:
        return (self.package, self.old_version, self.new_version)


@dataclass(frozen=True)
class PairResult:
    candidate: Candidate
    label: str
    excluded: bool
    reason: str | None
    score_value: int | None
    alert: bool
    escalate: bool
    rule_ids: tuple[str, ...]
    finding_count: int
    incomplete: bool
    files_changed: int
    rejection: tuple[dict[str, str], ...] = ()


@dataclass(frozen=True)
class BenignProvenance:
    source: str
    retrieved: str
    names: tuple[str, ...]


@dataclass(frozen=True)
class AdvisoryScan:
    json_files: int
    parsed: int
    npm_records: int
    npm_packages: int
    ranges_only_packages: int


@dataclass
class Counters:
    values: dict[str, int]

    def add(self, reason: str, amount: int = 1) -> None:
        self.values[reason] = self.values.get(reason, 0) + amount


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def as_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def parse_time(text: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


# --------------------------------------------------------------------------- inputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="measure.py",
        description="Static-only measurement of the M2 npm rules against OSSF advisories.",
    )
    parser.add_argument("--ossf-dir", type=Path, help="local clone of ossf/malicious-packages")
    parser.add_argument("--benign-list", type=Path, help="committed npm package name list")
    parser.add_argument("--seed", type=int, help="sampling seed (default 1234)")
    parser.add_argument("--max-pairs", type=int, help="cap per candidate pool (default 200)")
    parser.add_argument("--config", type=Path, help="TOML file supplying the four inputs above")
    parser.add_argument(
        "--pkgwatch-config", type=Path, help="product config TOML for sandbox limits and weights"
    )
    parser.add_argument(
        "--out-dir", type=Path, default=Path(__file__).resolve().parent / "out", help="results dir"
    )
    parser.add_argument("--offline", action="store_true", help="use cached docs and artifacts only")
    parser.add_argument("--refresh-docs", action="store_true", help="re-fetch cached registry docs")
    parser.add_argument("--sleep", type=float, help="delay between HTTP requests (default 0.2)")
    parser.add_argument(
        "--keep-extracted", action="store_true", help="leave extracted trees under data/raw"
    )
    parser.add_argument("--limit", type=int, help="evaluate at most this many pairs (debugging)")
    parser.add_argument(
        "--allow-tarball-host",
        action="append",
        dest="hosts",
        help=f"tarball host allow-list (default {NPM_REGISTRY_HOST})",
    )
    parser.add_argument(
        "--with-evidence", type=Path, help="write per-finding evidence here (keep it out of git)"
    )
    parser.add_argument("--ossf-commit", help="commit SHA if the clone cannot resolve it itself")
    parser.add_argument("--self-check", action="store_true", help="verify the harness, no network")
    return parser


def resolve_inputs(args: argparse.Namespace) -> Inputs:
    from_file: dict[str, Any] = {}
    if args.config is not None:
        from_file = tomllib.loads(Path(args.config).read_text(encoding="utf-8"))

    def pick(cli: Any, key: str, default: Any = None) -> Any:
        if cli is not None:
            return cli
        return from_file.get(key, default)

    ossf_dir = pick(args.ossf_dir, "ossf_dir")
    benign_list = pick(args.benign_list, "benign_list")
    if ossf_dir is None or benign_list is None:
        raise MeasureError(
            "TODO: --ossf-dir and --benign-list (or a --config supplying both) are required. "
            "Neither has a default: this script will not invent an advisory source or a list."
        )
    seed = int(pick(args.seed, "seed", 1234))
    max_pairs = int(pick(args.max_pairs, "max_pairs", 200))
    if seed < 0:
        raise MeasureError(f"seed must be >= 0, got {seed}")
    if max_pairs < 1:
        raise MeasureError(f"max_pairs must be >= 1, got {max_pairs}")
    hosts: tuple[str, ...] = tuple(args.hosts) if args.hosts else (NPM_REGISTRY_HOST,)
    return Inputs(
        ossf_dir=Path(ossf_dir),
        benign_list=Path(benign_list),
        seed=seed,
        max_pairs=max_pairs,
        out_dir=Path(args.out_dir),
        config_path=args.pkgwatch_config,
        offline=bool(args.offline),
        refresh_docs=bool(args.refresh_docs),
        sleep_seconds=float(pick(args.sleep, "sleep", 0.2)),
        keep_extracted=bool(pick(args.keep_extracted, "keep_extracted", False)),
        limit=args.limit,
        tarball_hosts=hosts,
        with_evidence=args.with_evidence,
        ossf_commit=args.ossf_commit,
    )


def load_config(path: Path | None) -> Config:
    return Config.load(path) if path is not None else Config()


def temp_config(root: Path) -> Config:
    """A Config rooted in a scratch directory, so the self-check never touches ``data/``."""
    return Config(paths=PathsConfig(data_dir=root, db_path=root / "pkgwatch.sqlite3"))


def read_benign_list(path: Path) -> BenignProvenance:
    """Names plus the header provenance the brief requires, checked mechanically."""
    if not path.is_file():
        raise MeasureError(f"TODO: benign list {path} does not exist; supply a committed name list")
    source: str | None = None
    retrieved: str | None = None
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        if text.startswith("#"):
            header = re.match(r"#\s*(source|retrieved)\s*:\s*(.+)$", text, re.IGNORECASE)
            if header is not None:
                value = header.group(2).strip()
                if header.group(1).lower() == "source":
                    source = value
                else:
                    retrieved = value
            continue
        names.append(text)
    missing = [
        key for key, value in (("source", source), ("retrieved", retrieved)) if value is None
    ]
    if missing:
        raise MeasureError(
            f"TODO: {path} needs a header comment declaring {', '.join(missing)} "
            "(`# source: <where this list came from>`, `# retrieved: YYYY-MM-DD`). This script "
            "never fetches a popularity list, so its provenance has to be written down."
        )
    if not names:
        raise MeasureError(
            f"TODO: {path} declares provenance but lists no package names; the benign set is empty."
        )
    if not RETRIEVED_RE.fullmatch(retrieved or ""):
        raise MeasureError(f"retrieved date {retrieved!r} is not YYYY-MM-DD")
    return BenignProvenance(source=source or "", retrieved=retrieved or "", names=tuple(names))


def git_commit(clone: Path, override: str | None) -> str:
    """Resolve the advisory clone's commit without shelling out."""
    if override:
        return override
    head = clone / ".git" / "HEAD"
    if not head.is_file():
        raise MeasureError(
            f"TODO: {clone} is not a git clone, so the advisory commit SHA cannot be recorded, and "
            "SPEC §7.4 requires it for provenance. Re-clone it or pass --ossf-commit."
        )
    text = head.read_text(encoding="utf-8").strip()
    if not text.startswith("ref:"):
        return text
    ref = text.split(":", 1)[1].strip()
    loose = clone / ".git" / ref
    if loose.is_file():
        return loose.read_text(encoding="utf-8").strip()
    packed = clone / ".git" / "packed-refs"
    if packed.is_file():
        for line in packed.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith(("#", "^")) and line.endswith(f" {ref}"):
                return line.split(" ", 1)[0]
    raise MeasureError(f"TODO: cannot resolve git ref {ref!r} in {clone}; pass --ossf-commit")


def read_license(clone: Path) -> dict[str, Any]:
    candidates = [clone / name for name in ("LICENSE", "LICENSE.md", "LICENCE", "COPYING")]
    path = next((c for c in candidates if c.is_file()), None)
    if path is None:
        raise MeasureError(
            f"TODO: no LICENSE file in {clone}. SPEC §7.4 records the advisory license as "
            "Apache-2.0; that claim cannot be re-verified from this directory, so the run stops."
        )
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    first = next((line.strip() for line in text.splitlines() if line.strip()), "")
    return {
        "file": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "first_line": first[:120],
        "apache_2_boilerplate_seen": APACHE_MARKER in text[:4000].lower(),
        "spec_claim": "Apache-2.0 (SPEC §7.4, verified 2026-11-05)",
    }


# ----------------------------------------------------------------------- osv records


def iter_json_files(root: Path) -> Iterator[Path]:
    for path in sorted(root.rglob("*.json")):
        if ".git" in path.parts or "node_modules" in path.parts:
            continue
        if path.is_file():
            yield path


def advisory_identity(record: Mapping[str, Any]) -> tuple[str, str] | None:
    """(ecosystem, name) from either OSV layout, or None if the record says nothing."""
    for entry in as_list(record.get("affected")):
        package = as_dict(as_dict(entry).get("package"))
        ecosystem, name = as_str(package.get("ecosystem")), as_str(package.get("name"))
        if ecosystem and name:
            return ecosystem.lower(), name
    top = as_dict(record.get("package"))
    ecosystem, name = as_str(top.get("ecosystem")), as_str(top.get("name"))
    if ecosystem and name:
        return ecosystem.lower(), name
    return None


def explicit_versions(record: Mapping[str, Any], name: str) -> tuple[list[str], bool]:
    """Versions the record names outright, plus whether a ranges-only record was seen.

    A ranges-only record needs the interval comparator SPEC §6.4 assigns to ``pkgwatch.version``,
    which does not exist yet, so its versions are counted and skipped rather than guessed.
    """
    found: list[str] = []
    ranges_only = False
    for entry in as_list(record.get("affected")):
        body = as_dict(entry)
        package = as_dict(body.get("package")) or as_dict(record.get("package"))
        if as_str(package.get("name")) not in (None, name):
            continue
        listed = [v for v in (as_str(item) for item in as_list(body.get("versions"))) if v]
        if listed:
            found.extend(listed)
        elif as_list(body.get("ranges")):
            ranges_only = True
    return found, ranges_only


def scan_advisories(ossf_dir: Path) -> tuple[dict[str, list[str]], AdvisoryScan]:
    """npm package -> the affected versions its advisories state explicitly."""
    if not ossf_dir.is_dir():
        raise MeasureError(
            f"TODO: --ossf-dir {ossf_dir} is not a directory. Clone ossf/malicious-packages "
            "locally; this script does not fetch advisories."
        )
    if not (ossf_dir / "advisories").is_dir():
        raise MeasureError(
            f"TODO: {ossf_dir} has no `advisories/` directory, so it is not an "
            "ossf/malicious-packages clone as SPEC §7.4 describes it. This run will not walk "
            "an unrelated tree looking for json files."
        )
    by_package: dict[str, list[str]] = {}
    counters = Counters({})
    seen = parsed = npm_records = 0
    ranges_only: set[str] = set()
    for path in iter_json_files(ossf_dir):
        seen += 1
        if seen > ADVISORY_FILE_LIMIT:
            raise MeasureError(
                f"TODO: {ossf_dir} holds more than {ADVISORY_FILE_LIMIT} json files, which is not "
                "an advisory clone. Point --ossf-dir at a local ossf/malicious-packages checkout."
            )
        try:
            record = as_dict(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            counters.add("OSV_FILE_UNREADABLE")
            continue
        identity = advisory_identity(record)
        if identity is None:
            counters.add("OSV_NO_PACKAGE_IDENTITY")
            continue
        parsed += 1
        ecosystem, name = identity
        if ecosystem != "npm":
            counters.add("NOT_NPM")
            continue
        npm_records += 1
        versions, ranges_only_record = explicit_versions(record, name)
        if versions:
            bucket = by_package.setdefault(name, [])
            bucket.extend(v for v in versions if v not in bucket)
        elif ranges_only_record:
            ranges_only.add(name)
    if not by_package:
        raise MeasureError(
            f"TODO: no npm advisory under {ossf_dir} states affected versions explicitly "
            f"({seen} json files read, {parsed} with a package identity, {npm_records} npm, "
            f"{len(ranges_only)} ranges-only). Either point --ossf-dir at records carrying "
            "`affected[].versions`, or land the SPEC §6.4 version comparator so ranges events can "
            "be evaluated. Guessing versions is not an option."
        )
    scan = AdvisoryScan(seen, parsed, npm_records, len(by_package), len(ranges_only))
    return by_package, scan


# ------------------------------------------------------------------ registry access


class Registry:
    """npm documents and tarballs, cached under the gitignored ``data/raw`` tree."""

    def __init__(self, inputs: Inputs, config: Config) -> None:
        self.inputs = inputs
        self.extract_dir = config.paths.extract_dir
        self.docs_dir = config.paths.raw_dir / "docs"
        self.artifacts_dir = config.paths.artifacts_dir
        for directory in (self.docs_dir, self.artifacts_dir, self.extract_dir):
            directory.mkdir(parents=True, exist_ok=True)
        self.fetches = 0
        self.cache_hits = 0

    def cache_path(self, name: str) -> Path:
        return self.docs_dir / f"{slug(name)}.json"

    def artifact_path(self, name: str, version: str) -> Path:
        return self.artifacts_dir / f"{slug(name)}-{slug(version)}.tgz"

    def doc(self, name: str) -> dict[str, Any] | None:
        if not SAFE_NAME_RE.fullmatch(name):
            return None
        cache = self.cache_path(name)
        if cache.is_file() and not self.inputs.refresh_docs:
            self.cache_hits += 1
            return as_dict(json.loads(cache.read_text(encoding="utf-8")))
        if self.inputs.offline:
            return None
        url = NPM_DOC_URL.format(name=urllib.parse.quote(name, safe="@"))
        body = self.get(url)
        if body is None:
            return None
        try:
            text = body.decode("utf-8")
            document = as_dict(json.loads(text))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return None
        cache.write_text(text, encoding="utf-8")
        return document

    def tarball(self, url: str, name: str, version: str) -> tuple[Path | None, str | None]:
        if not url:
            return None, SKIP_TARBALL_URL
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.hostname not in self.inputs.tarball_hosts:
            return None, XCLUDE_OFFSITE
        target = self.artifact_path(name, version)
        if target.is_file() and target.stat().st_size > 0:
            self.cache_hits += 1
            return target, None
        if self.inputs.offline:
            return None, ARTIFACT_NOT_CACHED
        body = self.get(url)
        if body is None:
            return None, XCLUDE_FETCH_FAILED
        partial = target.with_name(f"{target.name}.part")
        partial.write_bytes(body)
        partial.replace(target)
        return target, None

    def get(self, url: str) -> bytes | None:
        """One GET, nothing more. URLs are either the SPEC §3 document template or an
        allow-listed tarball URL; nothing else reaches this function."""
        request = urllib.request.Request(  # noqa: S310 - https + host allow-list checked upstream
            url, headers={"User-Agent": USER_AGENT}
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - same guard as above
                request, timeout=DOC_TIMEOUT_SECONDS
            ) as response:
                self.fetches += 1
                body: bytes = response.read()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            detail = getattr(exc, "code", type(exc).__name__)
            print(f"fetch failed for {url}: {detail}", file=sys.stderr)
            return None
        if self.inputs.sleep_seconds > 0:
            time.sleep(self.inputs.sleep_seconds)
        return body


def version_times(doc: Mapping[str, Any]) -> dict[str, datetime]:
    """version -> published_at, ordered by the registry ``time`` map (SPEC §6.1)."""
    time_map = as_dict(doc.get("time"))
    versions = as_dict(doc.get("versions"))
    out: dict[str, datetime] = {}
    for key, value in time_map.items():
        if key in REGISTRY_TIME_KEYS or key not in versions:
            continue
        moment = parse_time(str(value))
        if moment is not None:
            out[key] = moment
    return out


def predecessor(timetable: Mapping[str, datetime], version: str) -> tuple[str | None, str | None]:
    """The release published immediately before ``version``, ordered by published_at alone."""
    target = timetable.get(version)
    if target is None:
        return None, SKIP_VERSION_NOT_IN_DOC
    earlier = sorted(
        (moment, name) for name, moment in timetable.items() if name != version and moment < target
    )
    if not earlier:
        return None, SKIP_NO_PREDECESSOR
    moment, name = earlier[-1]
    if any(other == moment for other, _ in earlier[:-1]):
        return None, SKIP_AMBIGUOUS_PREDECESSOR
    return name, None


def install_script_in_doc(doc: Mapping[str, Any], versions: Sequence[str]) -> bool:
    """Whether either side declares an install-time script, per the registry document.

    SPEC §3 lets family 1 read ``scripts`` from the doc snapshot, and the doc is npm's own copy of
    the published ``package.json``. Reading the tarball's copy here would need the rules, which
    only see added lines -- so a package whose shipped manifest disagrees with its doc is
    mis-stratified. See README, "what is not measured".
    """
    table = as_dict(doc.get("versions"))
    for version in versions:
        scripts = as_dict(as_dict(table.get(version)).get("scripts"))
        if any(key in scripts for key in INSTALL_SCRIPT_KEYS):
            return True
    return False


def check_digests(payload: bytes, dist: Mapping[str, Any]) -> str | None:
    """Verify what the registry said about these bytes before they are analysed."""
    integrity = as_str(dist.get("integrity"))
    shasum = as_str(dist.get("shasum"))
    if integrity is not None and integrity.startswith("sha512-"):
        try:
            expected = base64.b64decode(integrity[len("sha512-") :], validate=True)
        except ValueError:
            return XCLUDE_DIGEST
        if hashlib.sha512(payload).digest() != expected:
            return XCLUDE_DIGEST
    if shasum is not None and hashlib.sha1(payload).hexdigest() != shasum.lower():  # noqa: S324
        # sha1 is the registry's legacy shasum, compared only when the document supplies it.
        return XCLUDE_DIGEST
    if integrity is None and shasum is None:
        return XCLUDE_NO_DIGEST
    return None


# ------------------------------------------------------------------------- per pair


class PairEvaluator:
    def __init__(self, registry: Registry, config: Config, sink: Path | None) -> None:
        self.registry = registry
        self.config = config
        self.families = families_by_rule_id()
        self.set_version = rule_set_version()
        self.evidence: list[dict[str, Any]] = []
        self.sink = sink

    def run(self, candidate: Candidate, label: str) -> PairResult:
        doc = self.registry.doc(candidate.package)
        if doc is None:
            return self.plain(candidate, label, excluded=True, reason=SKIP_DOC_UNAVAILABLE)
        table = as_dict(doc.get("versions"))
        payload: dict[str, bytes] = {}
        for version in (candidate.old_version, candidate.new_version):
            dist = as_dict(as_dict(table.get(version)).get("dist"))
            path, reason = self.registry.tarball(
                str(dist.get("tarball") or ""), candidate.package, version
            )
            if path is None:
                return self.plain(candidate, label, excluded=True, reason=reason)
            raw = path.read_bytes()
            mismatch = check_digests(raw, dist)
            if mismatch is not None:
                return self.plain(candidate, label, excluded=True, reason=mismatch)
            payload[version] = raw

        pair_dir = (
            f"{slug(candidate.package)}-{slug(candidate.old_version)}-{slug(candidate.new_version)}"
        )
        workdir = self.registry.extract_dir / pair_dir
        if workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)
        workdir.mkdir(parents=True, exist_ok=True)
        trees: dict[str, ExtractionResult] = {}
        rejections: list[dict[str, str]] = []
        try:
            for version, side in ((candidate.old_version, "old"), (candidate.new_version, "new")):
                archive = workdir / f"{side}.tgz"
                archive.write_bytes(payload[version])
                try:
                    trees[side] = extract_archive(archive, workdir / side, self.config.sandbox)
                except ArchiveRejected as exc:
                    rejections.append({"side": side, "code": exc.rejection.reason_code.value})
                except (OSError, ValueError) as exc:
                    rejections.append({"side": side, "code": type(exc).__name__})
            if rejections:
                return self.plain(
                    candidate, label, excluded=True, reason=XCLUDE_REJECTED, rejections=rejections
                )
            context = self.context(candidate, doc, table, trees)
            findings = run_rules(context)
            incomplete = analysis_incomplete(findings) or context.views_incomplete
            scored = score(
                findings,
                scoring=self.config.scoring,
                families=self.families,
                rule_set_version=self.set_version,
            )
            self.record_evidence(candidate, findings)
            return self.plain(
                candidate,
                label,
                excluded=incomplete,
                reason=XCLUDE_INCOMPLETE if incomplete else None,
                scored=scored,
                findings=findings,
                incomplete=incomplete,
                files_changed=len(context.changes),
                rejections=rejections,
            )
        finally:
            if not self.registry.inputs.keep_extracted:
                shutil.rmtree(workdir, ignore_errors=True)

    def context(
        self,
        candidate: Candidate,
        doc: Mapping[str, Any],
        table: Mapping[str, Any],
        trees: Mapping[str, ExtractionResult],
    ) -> DiffContext:
        moment = parse_time(str(as_dict(doc.get("time")).get(candidate.new_version, "")))
        if moment is None:
            raise MeasureError(
                f"no usable publication time for {candidate.package}@{candidate.new_version}"
            )
        return build_diff_context(
            ecosystem=Ecosystem.NPM,
            package_name=candidate.package,
            old_version=candidate.old_version,
            new_version=candidate.new_version,
            published_at=moment,
            old=trees["old"],
            new=trees["new"],
            limits=self.config.sandbox,
            metadata_before=as_dict(table.get(candidate.old_version)),
            metadata_after=as_dict(table.get(candidate.new_version)),
        )

    def plain(
        self,
        candidate: Candidate,
        label: str,
        *,
        excluded: bool,
        reason: str | None = None,
        scored: ScoreResult | None = None,
        findings: Sequence[Finding] = (),
        incomplete: bool = False,
        files_changed: int = 0,
        rejections: Sequence[dict[str, str]] = (),
    ) -> PairResult:
        value = scored.score if scored is not None else None
        return PairResult(
            candidate=candidate,
            label=label,
            excluded=excluded,
            reason=reason,
            score_value=value,
            alert=value is not None and value >= self.config.scoring.alert_threshold,
            escalate=value is not None and value >= self.config.scoring.escalate_threshold,
            rule_ids=tuple(sorted({finding.rule_id for finding in findings})),
            finding_count=len(findings),
            incomplete=incomplete,
            files_changed=files_changed,
            rejection=tuple(rejections),
        )

    def record_evidence(self, candidate: Candidate, findings: Sequence[Finding]) -> None:
        if self.sink is None:
            return
        self.evidence.extend(
            {
                "package": candidate.package,
                "new_version": candidate.new_version,
                "rule_id": finding.rule_id,
                "path": finding.path,
                "line_start": finding.line_start,
                "evidence": finding.evidence,
            }
            for finding in findings
        )

    def flush(self) -> None:
        if self.sink is None:
            return
        self.sink.parent.mkdir(parents=True, exist_ok=True)
        self.sink.write_text(
            "".join(
                f"{row['package']}\t{row['rule_id']}\t{row['path']}:{row['line_start']}\t"
                f"{row['evidence']}\n"
                for row in self.evidence
            ),
            encoding="utf-8",
        )


# -------------------------------------------------------------------------- sampling


def malicious_candidates(
    registry: Registry, by_package: Mapping[str, Sequence[str]], counters: Counters
) -> list[Candidate]:
    """Every usable (predecessor, affected) pair, sorted; capping happens in ``run``."""
    pool: list[Candidate] = []
    for name in sorted(by_package):
        if not SAFE_NAME_RE.fullmatch(name):
            counters.add(SKIP_UNSAFE_NAME)
            continue
        doc = registry.doc(name)
        if doc is None:
            counters.add(SKIP_DOC_UNAVAILABLE)
            continue
        if as_str(doc.get("name")) != name:
            counters.add(SKIP_NAME_NOT_IN_DOC)
            continue
        timetable = version_times(doc)
        for version in sorted(set(by_package[name])):
            if not SAFE_VERSION_RE.fullmatch(version):
                counters.add(SKIP_UNSAFE_NAME)
                continue
            before, reason = predecessor(timetable, version)
            if before is None:
                counters.add(reason or SKIP_NO_PREDECESSOR)
                continue
            pool.append(
                Candidate(
                    package=name,
                    old_version=before,
                    new_version=version,
                    published_at=timetable[version].isoformat(),
                    stratum=STRATUM_MALICIOUS,
                    origin="ossf/malicious-packages",
                )
            )
    return sorted(pool, key=Candidate.key)


def benign_candidates(
    registry: Registry,
    names: Sequence[str],
    excluded: frozenset[str],
    counters: Counters,
) -> tuple[list[Candidate], list[Candidate]]:
    """The two benign strata, sorted: install-script hard negatives, then the rest."""
    install: list[Candidate] = []
    plain: list[Candidate] = []
    for name in sorted(set(names)):
        if name in excluded:
            counters.add(SKIP_OVERLAP)
            continue
        if not SAFE_NAME_RE.fullmatch(name):
            counters.add(SKIP_UNSAFE_NAME)
            continue
        doc = registry.doc(name)
        if doc is None:
            counters.add(SKIP_DOC_UNAVAILABLE)
            continue
        if as_str(doc.get("name")) != name:
            counters.add(SKIP_NAME_NOT_IN_DOC)
            continue
        timetable = version_times(doc)
        newest = max(sorted(timetable), key=lambda version: timetable[version])
        before, reason = predecessor(timetable, newest)
        if before is None:
            counters.add(reason or SKIP_NO_PREDECESSOR)
            continue
        candidate = Candidate(
            package=name,
            old_version=before,
            new_version=newest,
            published_at=timetable[newest].isoformat(),
            stratum="",
            origin="benign_list",
        )
        if install_script_in_doc(doc, (before, newest)):
            install.append(with_stratum(candidate, STRATUM_BENIGN_INSTALL))
        else:
            plain.append(with_stratum(candidate, STRATUM_BENIGN_PLAIN))
    return sorted(install, key=Candidate.key), sorted(plain, key=Candidate.key)


def with_stratum(candidate: Candidate, stratum: str) -> Candidate:
    return Candidate(
        package=candidate.package,
        old_version=candidate.old_version,
        new_version=candidate.new_version,
        published_at=candidate.published_at,
        stratum=stratum,
        origin=candidate.origin,
    )


def capped(pool: Sequence[Candidate], cap: int, seed: int) -> list[Candidate]:
    """Deterministic sample: sort, draw with the seed, sort again."""
    ordered = sorted(pool, key=Candidate.key)
    if len(ordered) <= cap:
        return ordered
    # Seed is for reproducibility of the draw, not secrecy.
    return sorted(random.Random(seed).sample(ordered, cap), key=Candidate.key)  # noqa: S311


# ---------------------------------------------------------------------------- metrics


def summarise(results: Sequence[PairResult], config: Config) -> dict[str, Any]:
    kept = [row for row in results if not row.excluded]
    groups = {
        "malicious": [row for row in kept if row.candidate.stratum == STRATUM_MALICIOUS],
        STRATUM_BENIGN_INSTALL: [
            row for row in kept if row.candidate.stratum == STRATUM_BENIGN_INSTALL
        ],
        STRATUM_BENIGN_PLAIN: [
            row for row in kept if row.candidate.stratum == STRATUM_BENIGN_PLAIN
        ],
        "benign_all": [row for row in kept if row.candidate.stratum != STRATUM_MALICIOUS],
    }
    metrics: dict[str, Any] = {
        "thresholds": {
            "alert": config.scoring.alert_threshold,
            "escalate": config.scoring.escalate_threshold,
            "note": "Only the two thresholds SPEC §5 declares; none is tuned here.",
        },
        "groups": {name: group_metrics(group) for name, group in groups.items()},
        "separation": {},
        "excluded": excluded_counts(results),
        "sandbox_rejections": rejection_counts(results),
    }
    for key, threshold in (
        ("alert", config.scoring.alert_threshold),
        ("escalate", config.scoring.escalate_threshold),
    ):
        hit = (lambda row: row.alert) if key == "alert" else (lambda row: row.escalate)
        mal = rate(groups["malicious"], hit)
        benign = rate(groups["benign_all"], hit)
        metrics["separation"][key] = {
            "threshold": threshold,
            "recall": mal,
            "false_alarm_rate": benign,
            "false_alarm_rate_hard_negatives": rate(groups[STRATUM_BENIGN_INSTALL], hit),
            "youden_j": round(mal - benign, 4)
            if groups["malicious"] and groups["benign_all"]
            else None,
        }
    return metrics


def group_metrics(group: Sequence[PairResult]) -> dict[str, Any]:
    scores = [row.score_value or 0 for row in group]
    return {
        "pairs": len(group),
        "any_finding": sum(1 for row in group if row.finding_count),
        "at_alert": sum(1 for row in group if row.alert),
        "at_escalate": sum(1 for row in group if row.escalate),
        "median_score": statistics.median(scores) if scores else None,
        "max_score": max(scores, default=None),
        "rule_pairs": rule_counts(group),
    }


def rate(group: Sequence[PairResult], hit: Callable[[PairResult], bool]) -> float:
    if not group:
        return 0.0
    return round(sum(1 for row in group if hit(row)) / len(group), 4)


def rule_counts(group: Sequence[PairResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in group:
        for rule_id in row.rule_ids:
            counts[rule_id] = counts.get(rule_id, 0) + 1
    return dict(sorted(counts.items()))


def excluded_counts(results: Sequence[PairResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in results:
        if row.excluded and row.reason:
            counts[row.reason] = counts.get(row.reason, 0) + 1
    return dict(sorted(counts.items()))


def rejection_counts(results: Sequence[PairResult]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in results:
        for entry in row.rejection:
            counts[entry["code"]] = counts.get(entry["code"], 0) + 1
    return dict(sorted(counts.items()))


# --------------------------------------------------------------------------- outputs


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def pairs_payload(
    candidates: Sequence[Candidate], pool_sizes: Mapping[str, int], counters: Mapping[str, int]
) -> dict[str, Any]:
    return {
        "note": "Coordinates only: no package content, no downloads, no findings text.",
        "count": len(candidates),
        "pool_sizes": dict(sorted(pool_sizes.items())),
        "skipped": dict(sorted(counters.items())),
        "per_stratum": {
            stratum: sum(1 for row in candidates if row.stratum == stratum)
            for stratum in sorted({row.stratum for row in candidates})
        },
        "pairs": [
            {
                "package": row.package,
                "old_version": row.old_version,
                "new_version": row.new_version,
                "published_at": row.published_at,
                "stratum": row.stratum,
                "origin": row.origin,
            }
            for row in sorted(candidates, key=Candidate.key)
        ],
    }


def results_rows(results: Sequence[PairResult]) -> list[dict[str, Any]]:
    return [
        {
            "package": row.candidate.package,
            "old_version": row.candidate.old_version,
            "new_version": row.candidate.new_version,
            "stratum": row.candidate.stratum,
            "label": row.label,
            "score": row.score_value,
            "alert": row.alert,
            "escalate": row.escalate,
            "rule_ids": list(row.rule_ids),
            "finding_count": row.finding_count,
            "files_changed": row.files_changed,
            "analysis_incomplete": row.incomplete,
            "excluded": row.excluded,
            "reason": row.reason,
        }
        for row in sorted(results, key=lambda row: row.candidate.key())
    ]


def engine_payload(config: Config) -> dict[str, Any]:
    weights = config.scoring
    return {
        "rule_set_version": rule_set_version(),
        "rules": [
            {
                "rule_id": rule.rule_id,
                "rule_version": rule.rule_version,
                "severity": rule.severity.value,
                "families": sorted(family.value for family in rule.families),
                "ecosystems": sorted(e.value for e in rule.ecosystems),
                "weight_base": weights.severity.model_dump()[rule.severity.value],
            }
            for rule in RULES
        ],
        "weights": {
            "weights_version": weights.weights_version,
            "severity": weights.severity.model_dump(),
            "instance_weights": list(weights.decay.instance_weights),
            "max_multiplier": weights.decay.max_multiplier,
            "corroboration": weights.corroboration.model_dump(),
            "alert_threshold": weights.alert_threshold,
            "escalate_threshold": weights.escalate_threshold,
        },
        "sandbox_limits": config.sandbox.model_dump(mode="json"),
    }


def run(inputs: Inputs) -> int:
    config = load_config(inputs.config_path)
    registry = Registry(inputs, config)
    counters = Counters({})

    by_package, scan = scan_advisories(inputs.ossf_dir)
    commit = git_commit(inputs.ossf_dir, inputs.ossf_commit)
    license_info = read_license(inputs.ossf_dir)
    benign = read_benign_list(inputs.benign_list)

    mal_pool = malicious_candidates(registry, by_package, counters)
    overlap = frozenset(row.package for row in mal_pool)
    install_pool, plain_pool = benign_candidates(registry, benign.names, overlap, counters)
    mal = capped(mal_pool, inputs.max_pairs, inputs.seed)
    selected = (
        mal
        + capped(install_pool, inputs.max_pairs, inputs.seed)
        + capped(plain_pool, inputs.max_pairs, inputs.seed)
    )
    pool_sizes = {
        "malicious_pool": len(mal_pool),
        "benign_install_script_pool": len(install_pool),
        "benign_no_install_script_pool": len(plain_pool),
        "selected_before_limit": len(selected),
    }
    if inputs.limit is not None:
        selected = selected[: inputs.limit]
        pool_sizes["limited_to"] = inputs.limit

    evaluator = PairEvaluator(registry, config, inputs.with_evidence)
    results: list[PairResult] = []
    for index, candidate in enumerate(selected, start=1):
        label = "malicious" if candidate.stratum == STRATUM_MALICIOUS else "benign"
        print(
            f"[{index}/{len(selected)}] {candidate.package} "
            f"{candidate.old_version} -> {candidate.new_version} ({label})",
            file=sys.stderr,
        )
        results.append(evaluator.run(candidate, label))
    evaluator.flush()

    write_json(inputs.out_dir / "pairs.json", pairs_payload(selected, pool_sizes, counters.values))
    write_json(inputs.out_dir / "results.json", results_rows(results))
    write_json(inputs.out_dir / "metrics.json", summarise(results, config))
    write_json(
        inputs.out_dir / "run.json",
        {
            "generated_at": now_iso(),
            "static_only": True,
            "inputs": {
                "ossf_dir": str(inputs.ossf_dir),
                "benign_list": str(inputs.benign_list),
                "seed": inputs.seed,
                "max_pairs": inputs.max_pairs,
                "offline": inputs.offline,
                "refresh_docs": inputs.refresh_docs,
                "limit": inputs.limit,
                "tarball_hosts": list(inputs.tarball_hosts),
                "pkgwatch_config": str(inputs.config_path)
                if inputs.config_path
                else "product defaults",
                "evidence_file": str(inputs.with_evidence) if inputs.with_evidence else None,
            },
            "advisory_source": {
                "repository": "ossf/malicious-packages",
                "commit": commit,
                "license": license_info,
                "json_files_seen": scan.json_files,
                "osv_records_with_identity": scan.parsed,
                "npm_records": scan.npm_records,
                "npm_packages_with_explicit_versions": scan.npm_packages,
                "ranges_only_packages_skipped": scan.ranges_only_packages,
                "spec_claim": "SPEC §7.4 says advisories are under `advisories/`, Apache-2.0.",
            },
            "benign_source": {
                "source": benign.source,
                "retrieved": benign.retrieved,
                "names": len(benign.names),
                "note": "Operator-supplied; this script never fetches a popularity list.",
            },
            "engine": engine_payload(config),
            "toolchain": {
                "python": sys.version,
                "platform": sys.platform,
                "registry_http_fetches": registry.fetches,
                "cache_hits": registry.cache_hits,
            },
            "counters": dict(sorted(counters.values.items())),
        },
    )
    print(
        f"wrote pairs.json, results.json, metrics.json, run.json to {inputs.out_dir}",
        file=sys.stderr,
    )
    return 0


# -------------------------------------------------------------------------- self-check


def self_check() -> int:
    """Exercise every harness decision with synthetic inputs. No network, no package bytes.

    The sandbox/diff/rules/score path is deliberately not driven from here: it is product code
    with its own suite. This checks the harness's own arithmetic and selection, which no product
    test covers.
    """
    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        if not condition:
            failures.append(name)

    record: dict[str, Any] = {
        "id": "SYNTH-1",
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "synth-pkg"},
                "versions": ["1.1.0", "1.2.0"],
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.1.0"}]}],
            }
        ],
    }
    check("advisory identity read", advisory_identity(record) == ("npm", "synth-pkg"))
    check(
        "explicit versions read",
        explicit_versions(record, "synth-pkg") == (["1.1.0", "1.2.0"], False),
    )
    ranges_only: dict[str, Any] = {
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "synth-pkg"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}],
            }
        ]
    }
    check("ranges-only is not guessed", explicit_versions(ranges_only, "synth-pkg") == ([], True))
    check(
        "ecosystem case folded",
        advisory_identity({"affected": [{"package": {"ecosystem": "PyPI", "name": "x"}}]})
        == ("pypi", "x"),
    )
    check("unreadable record skipped", advisory_identity({"id": "X"}) is None)

    def synth_dist(version: str) -> dict[str, Any]:
        return {
            "tarball": f"https://registry.npmjs.org/synth-pkg/-/synth-pkg-{version}.tgz",
            "integrity": "sha512-" + base64.b64encode(b"not-verified-offline").decode(),
            "shasum": "0" * 40,
            "size": 1,
        }

    doc: dict[str, Any] = {
        "name": "synth-pkg",
        "versions": {
            "1.0.0": {"scripts": {"test": "echo harmless"}, "dist": synth_dist("1.0.0")},
            "1.1.0": {"scripts": {"postinstall": "echo harmless"}, "dist": synth_dist("1.1.0")},
            "1.2.0": {"scripts": {}, "dist": synth_dist("1.2.0")},
            "2.0.0-beta": {"scripts": {}, "dist": synth_dist("2.0.0-beta")},
        },
        "time": {
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "1.0.0": "2021-01-01T00:00:00.000Z",
            "1.1.0": "2022-02-02T00:00:00.000Z",
            "1.2.0": "2023-03-03T00:00:00.000Z",
            "2.0.0-beta": "2024-04-04T00:00:00.000Z",
        },
    }
    timetable = version_times(doc)
    check(
        "created/modified excluded from versions",
        set(timetable) == {"1.0.0", "1.1.0", "1.2.0", "2.0.0-beta"},
    )
    check("predecessor chosen by published_at", predecessor(timetable, "1.1.0") == ("1.0.0", None))
    check(
        "newest is last published",
        max(sorted(timetable), key=lambda v: timetable[v]) == "2.0.0-beta",
    )
    check(
        "first release has no predecessor",
        predecessor(timetable, "1.0.0")[1] == SKIP_NO_PREDECESSOR,
    )
    check("unknown version reported", predecessor(timetable, "9.9.9")[1] == SKIP_VERSION_NOT_IN_DOC)
    tied_times = dict(timetable)
    tied_times["1.1.0"] = timetable["1.2.0"]
    check(
        "same-second boundary tie is refused, not resolved by luck",
        predecessor(tied_times, "2.0.0-beta")[1] == SKIP_AMBIGUOUS_PREDECESSOR,
    )
    check(
        "a unique latest is still chosen when older ties exist",
        predecessor(tied_times, "1.2.0")[0] == "1.0.0",
    )
    check("install script seen in doc", install_script_in_doc(doc, ("1.0.0", "1.1.0")) is True)
    check(
        "install script side absent", install_script_in_doc(doc, ("1.0.0", "2.0.0-beta")) is False
    )
    check(
        "hostile scripts shape survives",
        install_script_in_doc({"versions": {"1.0.0": {"scripts": ["x"]}}}, ("1.0.0",)) is False,
    )
    check("scoped name allowed", SAFE_NAME_RE.fullmatch("@scope/name-1") is not None)
    check("traversal name refused", SAFE_NAME_RE.fullmatch("../etc/passwd") is None)
    check("backslash name refused", SAFE_NAME_RE.fullmatch("a\\b") is None)
    check(
        "scope is percent-encoded for the doc endpoint",
        NPM_DOC_URL.format(name=urllib.parse.quote("@scope/pkg", safe="@"))
        == "https://registry.npmjs.org/@scope%2Fpkg",
    )
    check("slug cannot traverse", slug("@scope/pkg") == "_scope_pkg")

    payload = b"harmless bytes"
    sri = {"integrity": "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()}
    check("sri integrity passes", check_digests(payload, sri) is None)
    check("sri mismatch excluded", check_digests(b"other bytes", sri) == XCLUDE_DIGEST)
    check(
        "sha1 shasum verifies",
        check_digests(payload, {"shasum": hashlib.sha1(payload).hexdigest()}) is None,  # noqa: S324
    )
    check("shasum mismatch excluded", check_digests(payload, {"shasum": "0" * 40}) == XCLUDE_DIGEST)
    check(
        "no digest at all is recorded, not ignored", check_digests(payload, {}) == XCLUDE_NO_DIGEST
    )

    pool = [
        Candidate("pkg-a", "1.0.0", f"1.{i}.0", "2024-01-01T00:00:00+00:00", "benign", "list")
        for i in range(12)
    ]
    draw = capped(pool, 5, 1234)
    check(
        "sampling is deterministic",
        [r.new_version for r in draw] == [r.new_version for r in capped(pool, 5, 1234)],
    )
    check("sampling respects the cap", len(draw) == 5)
    check(
        "sampling output stays sorted",
        [r.new_version for r in draw] == sorted(r.new_version for r in draw),
    )
    check("pool under cap is whole", capped(pool, 50, 1234) == sorted(pool, key=Candidate.key))

    config = Config()
    mal = PairResult(
        Candidate(
            "pkg-a", "1.0.0", "1.1.0", "2024-01-01T00:00:00+00:00", STRATUM_MALICIOUS, "ossf"
        ),
        "malicious",
        False,
        None,
        94,
        True,
        True,
        ("DYNAMIC_EVAL_ADDED", "NPM_INSTALL_SCRIPT_ADDED"),
        4,
        False,
        3,
    )
    hard = PairResult(
        Candidate(
            "pkg-b", "1.0.0", "1.1.0", "2024-01-01T00:00:00+00:00", STRATUM_BENIGN_INSTALL, "list"
        ),
        "benign",
        False,
        None,
        0,
        False,
        False,
        (),
        0,
        False,
        1,
    )
    soft = PairResult(
        Candidate(
            "pkg-d", "1.0.0", "1.1.0", "2024-01-01T00:00:00+00:00", STRATUM_BENIGN_PLAIN, "list"
        ),
        "benign",
        False,
        None,
        42,
        True,
        False,
        ("NET_ACCESS_ADDED",),
        1,
        False,
        2,
    )
    dropped = PairResult(
        Candidate(
            "pkg-e", "1.0.0", "1.1.0", "2024-01-01T00:00:00+00:00", STRATUM_BENIGN_PLAIN, "list"
        ),
        "benign",
        True,
        XCLUDE_DIGEST,
        None,
        False,
        False,
        (),
        0,
        False,
        0,
    )
    rejected = PairResult(
        Candidate(
            "pkg-f", "1.0.0", "1.1.0", "2024-01-01T00:00:00+00:00", STRATUM_MALICIOUS, "ossf"
        ),
        "malicious",
        True,
        XCLUDE_REJECTED,
        None,
        False,
        False,
        (),
        0,
        False,
        0,
        ({"side": "new", "code": "FILE_COUNT_EXCEEDED"},),
    )
    metrics = summarise([mal, hard, soft, dropped, rejected], config)
    check("malicious pair counted once", metrics["groups"]["malicious"]["pairs"] == 1)
    check("hard negative is its own group", metrics["groups"][STRATUM_BENIGN_INSTALL]["pairs"] == 1)
    check("excluded pairs leave the rates", metrics["groups"]["benign_all"]["pairs"] == 2)
    check("exclusion reason counted", metrics["excluded"].get(XCLUDE_DIGEST) == 1)
    check("rejection code counted", metrics["sandbox_rejections"].get("FILE_COUNT_EXCEEDED") == 1)
    check("alert recall", metrics["separation"]["alert"]["recall"] == 1.0)
    check("alert false alarm rate", metrics["separation"]["alert"]["false_alarm_rate"] == 0.5)
    check(
        "hard negative false alarm",
        metrics["separation"]["alert"]["false_alarm_rate_hard_negatives"] == 0.0,
    )
    check("escalate recall", metrics["separation"]["escalate"]["recall"] == 1.0)
    check(
        "thresholds are the declared ones",
        metrics["thresholds"]["alert"] == 40 and metrics["thresholds"]["escalate"] == 70,
    )
    check(
        "rule pairs tallied",
        metrics["groups"]["malicious"]["rule_pairs"]["NPM_INSTALL_SCRIPT_ADDED"] == 1,
    )

    check("engine payload lists the seven rules", len(engine_payload(config)["rules"]) == 7)
    check(
        "weights documented in run payload",
        engine_payload(config)["weights"]["weights_version"] == config.scoring.weights_version,
    )
    pairs_doc = pairs_payload([mal.candidate, hard.candidate], {"malicious": 2}, {"X": 1})
    check("pairs payload is coordinates only", "evidence" not in json.dumps(pairs_doc))
    check("pairs payload tallies strata", pairs_doc["per_stratum"][STRATUM_BENIGN_INSTALL] == 1)

    with tempfile.TemporaryDirectory() as staging:
        root = Path(staging)
        clone = root / "clone"
        (clone / "advisories" / "npm").mkdir(parents=True)
        (clone / "advisories" / "python").mkdir(parents=True)
        (clone / ".git").mkdir()
        (clone / "LICENSE").write_text("Apache License Version 2.0\n", encoding="utf-8")
        (clone / "advisories" / "npm" / "a.json").write_text(json.dumps(record), encoding="utf-8")
        (clone / "advisories" / "npm" / "b.json").write_text(
            json.dumps(ranges_only), encoding="utf-8"
        )
        pypi = {
            "affected": [
                {"package": {"ecosystem": "PyPI", "name": "synth-py"}, "versions": ["1.0"]}
            ]
        }
        (clone / "advisories" / "python" / "c.json").write_text(json.dumps(pypi), encoding="utf-8")
        (clone / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (clone / ".git" / "refs" / "heads").mkdir(parents=True)
        (clone / ".git" / "refs" / "heads" / "main").write_text(
            "deadbeef" + "0" * 32 + "\n", encoding="utf-8"
        )
        by_package, scan = scan_advisories(clone)
        check("only npm advisories kept", by_package == {"synth-pkg": ["1.1.0", "1.2.0"]})
        check("npm record counted", scan.npm_records == 2)
        check("ranges-only counted", scan.ranges_only_packages == 1)
        check("commit resolved from refs", git_commit(clone, None) == "deadbeef" + "0" * 32)
        check("license read from clone", read_license(clone)["apache_2_boilerplate_seen"] is True)
        stopped = False
        try:
            read_license(root / "clone2")
        except MeasureError:
            stopped = True
        check("missing LICENSE stops the run", stopped)

        elsewhere = root / "not-a-clone"
        elsewhere.mkdir()
        (elsewhere / "package.json").write_text("{}", encoding="utf-8")
        stopped = False
        try:
            scan_advisories(elsewhere)
        except MeasureError:
            stopped = True
        check("a directory without advisories/ is refused", stopped)

        list_path = root / "benign.txt"
        list_path.write_text(
            "# source: internal review\n# retrieved: 2026-11-06\nleft-pad\n", encoding="utf-8"
        )
        provenance = read_benign_list(list_path)
        check(
            "benign provenance parsed",
            provenance.source == "internal review" and provenance.names == ("left-pad",),
        )
        list_path.write_text("left-pad\n", encoding="utf-8")
        stopped = False
        try:
            read_benign_list(list_path)
        except MeasureError:
            stopped = True
        check("unattributed benign list stops the run", stopped)
        list_path.write_text(
            "# source: internal review\n# retrieved: 2026-11-06\n", encoding="utf-8"
        )
        stopped = False
        try:
            read_benign_list(list_path)
        except MeasureError:
            stopped = True
        check("a benign list with no names stops the run", stopped)

        doc_cache = root / "docs"
        doc_cache.mkdir()
        (doc_cache / "synth-pkg.json").write_text(json.dumps(doc), encoding="utf-8")
        offline_inputs = Inputs(
            ossf_dir=clone,
            benign_list=list_path,
            seed=1234,
            max_pairs=200,
            out_dir=root / "out",
            config_path=None,
            offline=True,
            refresh_docs=False,
            sleep_seconds=0.0,
            keep_extracted=False,
            limit=None,
            tarball_hosts=(NPM_REGISTRY_HOST,),
            with_evidence=None,
            ossf_commit=None,
        )
        registry = Registry(offline_inputs, temp_config(root))
        registry.docs_dir = doc_cache
        registry.artifacts_dir = root / "artifacts"
        counters = Counters({})
        pool = malicious_candidates(registry, by_package, counters)
        check("cached doc used offline", [row.new_version for row in pool] == ["1.1.0", "1.2.0"])
        check("no affected version was dropped", not counters.values)
        check("both affected versions usable", len(pool) == 2)
        if len(pool) == 2:
            check("predecessor of 1.1.0 is 1.0.0", pool[0].old_version == "1.0.0")
            check("predecessor is the previous publication", pool[1].old_version == "1.1.0")

        doc["time"]["1.2.0"] = "2022-01-01T00:00:00.000Z"
        (doc_cache / "synth-pkg.json").write_text(json.dumps(doc), encoding="utf-8")
        counters2 = Counters({})
        second = malicious_candidates(registry, by_package, counters2)
        check("out-of-order affected version still gets a predecessor", len(second) == 2)
        if len(second) == 2:
            check(
                "predecessor follows time, not the version string", second[1].old_version == "1.2.0"
            )

        pair = Candidate(
            "synth-pkg", "1.0.0", "1.1.0", "2022-02-02T00:00:00+00:00", STRATUM_MALICIOUS, "ossf"
        )
        with_doc = PairEvaluator(registry, temp_config(root), None)
        outcome = with_doc.run(pair, "malicious")
        check(
            "offline tarball fetch is excluded, not guessed",
            outcome.excluded and outcome.reason == ARTIFACT_NOT_CACHED,
        )
        uncached = Registry(offline_inputs, temp_config(root))
        uncached.docs_dir = root / "empty-docs"
        no_doc = PairEvaluator(uncached, temp_config(root), None)
        refused = no_doc.run(pair, "malicious")
        check(
            "offline doc miss is excluded, not guessed",
            refused.excluded and refused.reason == SKIP_DOC_UNAVAILABLE,
        )
        path, reason = registry.tarball("https://attacker.example/x.tgz", "synth-pkg", "1.1.0")
        check(
            "an off-site tarball URL is refused before it is fetched",
            path is None and reason == XCLUDE_OFFSITE,
        )
        path, reason = registry.tarball("", "synth-pkg", "1.1.0")
        check("a doc with no tarball URL is recorded", path is None and reason == SKIP_TARBALL_URL)
        path, reason = registry.tarball(
            "http://registry.npmjs.org/synth-pkg/-/synth-pkg-1.1.0.tgz", "synth-pkg", "1.1.0"
        )
        check("a plaintext tarball URL is refused", path is None and reason == XCLUDE_OFFSITE)
        widened_inputs = replace(offline_inputs, tarball_hosts=("attacker.example",))
        widened = Registry(widened_inputs, temp_config(root))
        widened.docs_dir = doc_cache
        widened.artifacts_dir = root / "artifacts"
        cached = widened.artifact_path("synth-pkg", "1.1.0")
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(b"written by the self-check, not downloaded")
        path, reason = widened.tarball("https://attacker.example/x.tgz", "synth-pkg", "1.1.0")
        check(
            "an explicitly allowed host passes the guard and serves the cache",
            path == cached and reason is None,
        )
        check(
            "no network happened during the self-check",
            registry.fetches == 0 and uncached.fetches == 0 and widened.fetches == 0,
        )

    if failures:
        print(f"SELF-CHECK FAILED: {', '.join(failures)}", file=sys.stderr)
        return 1
    print(
        "self-check passed: OSV selection, predecessor choice, digests, strata, sampling, "
        "metrics, provenance guards, offline behaviour"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    # Messages carry "SPEC §7.4" references; the console codepage on Windows is rarely UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    if args.self_check:
        return self_check()
    try:
        return run(resolve_inputs(args))
    except MeasureError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
