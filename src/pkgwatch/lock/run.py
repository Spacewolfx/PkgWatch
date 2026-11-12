"""Per-pair analysis for ``pkgwatch lock`` (SPEC §9.1).

This module only composes the modules that already exist: ``fetch`` retrieves the two
exact versions, ``sandbox`` is the sole route from a tarball to a file tree, ``diff``
builds the one object a rule may read, ``rules`` and ``score`` are called as they are.
No rule logic, severity or weight is reimplemented here, and no package content is ever
executed, imported, installed or built.

Pairs run concurrently up to ``[lock].concurrency``, and a pair that fails is recorded
with its stable code instead of aborting the run, so SPEC §9.1(7) holds: the report stays
complete and the exit code becomes 2.
"""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from pkgwatch.config import Config, LockConfig
from pkgwatch.diff import build_diff_context
from pkgwatch.diff.manifest import diff_root_manifests, manifest_parse_errors
from pkgwatch.fetch.cache import DownloadCache
from pkgwatch.fetch.npm import (
    FetchError,
    HttpClient,
    declared_unpacked_size,
    fetch_pair,
    fetch_release,
)
from pkgwatch.fetch.retry import RetryingClient, RetryPolicy
from pkgwatch.lock.baseline import BaselineEntry, BaselineKey, evidence_sha256
from pkgwatch.lockfile import (
    ChangedPair,
    LockfileError,
    LockPlan,
    NewPackage,
    ParsedLockfile,
    parse_lockfile,
    plan_lock_update,
)
from pkgwatch.models import (
    ArchiveFormat,
    ChangeType,
    DiffContext,
    Ecosystem,
    ExtractionResult,
    FileChange,
    Finding,
    RuleFamily,
    ScoreBoost,
    ScoreResult,
)
from pkgwatch.rules import families_by_rule_id, rule_set_version
from pkgwatch.rules.runner import analysis_incomplete, run_rules
from pkgwatch.sandbox import ArchiveRejected, cross_check_unpacked_size, extract_archive
from pkgwatch.score.engine import score

# The same stable codes ``compare`` prints. Exception messages can echo package-controlled
# text, so only a code is ever recorded.
ANALYSIS_INCOMPLETE = "ANALYSIS_INCOMPLETE"
INTERNAL_ERROR = "INTERNAL_ERROR"

# A brand-new package has no predecessor version. Rules only copy this into findings, and
# the report never shows it: the "no baseline" section is the honest label.
NO_BASELINE_VERSION = "(none)"


@dataclass(frozen=True)
class PairAnalysis:
    """One changed pair: its findings and score, or the stable code for why it failed.

    ``baselined`` counts the findings hidden by the baseline; ``acknowledged`` holds
    every finding the run produced after --ignore (before baseline hiding), which is
    what ``--update-baseline`` writes."""

    name: str
    old_version: str
    new_version: str
    findings: tuple[Finding, ...] = ()
    score: int = 0
    boosts: tuple[ScoreBoost, ...] = ()
    digests: tuple[str, str] | None = None
    files: tuple[int, int, int] = (0, 0, 0)
    ignored: tuple[tuple[str, int], ...] = ()
    baselined: int = 0
    acknowledged: tuple[Finding, ...] = ()
    error: str | None = None
    parse_problems: tuple[str, ...] = ()


@dataclass(frozen=True)
class NewPackageAnalysis:
    """One brand-new package analysed against an empty tree, or its stable failure code.

    ``informational`` holds the per-rule counts of family-4 findings: against an empty
    tree they describe what the package carries, not what changed, so they are reported
    separately and never scored (L2d). ``acknowledged`` is the pre-hide finding list for
    ``--update-baseline`` (see :class:`PairAnalysis`)."""

    name: str
    version: str
    findings: tuple[Finding, ...] = ()
    score: int = 0
    boosts: tuple[ScoreBoost, ...] = ()
    digest: str | None = None
    files: tuple[int, int, int] = (0, 0, 0)
    informational: tuple[tuple[str, int], ...] = ()
    ignored: tuple[tuple[str, int], ...] = ()
    baselined: int = 0
    acknowledged: tuple[Finding, ...] = ()
    error: str | None = None
    parse_problems: tuple[str, ...] = ()


@dataclass(frozen=True)
class LockRunResult:
    plan: LockPlan
    pairs: tuple[PairAnalysis, ...]
    new_analyses: tuple[NewPackageAnalysis, ...] = ()
    new_analysed: bool = True

    @property
    def incomplete(self) -> bool:
        return any(item.error is not None for item in self.pairs) or any(
            item.error is not None for item in self.new_analyses
        )


def run_lock(
    *,
    old_lock: Path,
    new_lock: Path,
    config: Config,
    client: HttpClient,
    ignored: Sequence[str] = (),
    max_pairs: int | None = None,
    cache: DownloadCache | None = None,
    analyse_new: bool = True,
    baseline: Sequence[BaselineEntry] = (),
    experimental: bool = False,
) -> LockRunResult:
    """Plan two lockfiles, then analyse every changed pair. Raises only for plan errors."""
    limits = (
        config.lock
        if max_pairs is None
        else config.lock.model_copy(update={"max_pairs": max_pairs})
    )
    old = _parse_side(old_lock, limits=limits, argument="--old")
    new = _parse_side(new_lock, limits=limits, argument="--new")
    plan = plan_lock_update(old, new, limits=limits, analyse_new=analyse_new)
    baseline_keys = frozenset(entry.key() for entry in baseline)
    retrying = RetryingClient(
        client,
        policy=RetryPolicy(
            max_attempts=config.lock.max_attempts,
            base_delay=config.lock.retry_base_delay_seconds,
            max_delay=config.lock.retry_max_delay_seconds,
            request_delay=config.lock.request_delay_seconds,
        ),
    )
    pairs = _analyse(
        plan.changed_pairs,
        config=config,
        client=retrying,
        ignored=ignored,
        cache=cache,
        baseline_keys=baseline_keys,
        experimental=experimental,
    )
    # Unsupported new packages are already counted as unanalysed by the plan; only the
    # registry-backed ones are fetched.
    unanalysed_new = {
        (item.name, item.new_version) for item in plan.unanalysed if item.old_version is None
    }
    analysable_new = tuple(
        item for item in plan.new_packages if (item.name, item.version) not in unanalysed_new
    )
    new_analyses = (
        _analyse_new_packages(
            analysable_new,
            config=config,
            client=retrying,
            ignored=ignored,
            cache=cache,
            baseline_keys=baseline_keys,
            experimental=experimental,
        )
        if analyse_new
        else ()
    )
    return LockRunResult(
        plan=plan, pairs=pairs, new_analyses=new_analyses, new_analysed=analyse_new
    )


def plan_lock(
    *,
    old_lock: Path,
    new_lock: Path,
    config: Config,
    max_pairs: int | None = None,
) -> LockPlan:
    """Parse two lockfiles and plan their update, without touching the network."""
    limits = (
        config.lock
        if max_pairs is None
        else config.lock.model_copy(update={"max_pairs": max_pairs})
    )
    old = _parse_side(old_lock, limits=limits, argument="--old")
    new = _parse_side(new_lock, limits=limits, argument="--new")
    return plan_lock_update(old, new, limits=limits)


def _parse_side(path: Path, *, limits: LockConfig, argument: str) -> ParsedLockfile:
    """Name the failing file by its CLI argument, never by its path or OS error text."""
    try:
        return parse_lockfile(path, limits=limits)
    except LockfileError as exc:
        raise LockfileError(exc.code, argument=argument) from None


def _analyse(
    changed: Sequence[ChangedPair],
    *,
    config: Config,
    client: HttpClient,
    ignored: Sequence[str],
    cache: DownloadCache | None,
    baseline_keys: frozenset[BaselineKey],
    experimental: bool = False,
) -> tuple[PairAnalysis, ...]:
    if not changed:
        return ()
    workers = max(1, min(config.lock.concurrency, len(changed)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(
            pool.map(
                lambda pair: _analyse_pair(
                    pair,
                    config=config,
                    client=client,
                    ignored=ignored,
                    cache=cache,
                    baseline_keys=baseline_keys,
                    experimental=experimental,
                ),
                changed,
            )
        )
    return tuple(sorted(results, key=lambda item: (item.name, item.old_version, item.new_version)))


def _analyse_pair(
    pair: ChangedPair,
    *,
    config: Config,
    client: HttpClient,
    ignored: Sequence[str],
    cache: DownloadCache | None,
    baseline_keys: frozenset[BaselineKey],
    experimental: bool = False,
) -> PairAnalysis:
    ignored_set = frozenset(ignored)
    try:
        with tempfile.TemporaryDirectory(prefix="pkgwatch-lock-") as temporary:
            workdir = Path(temporary)
            fetched = fetch_pair(
                name=pair.name,
                old_version=pair.old_version,
                new_version=pair.new_version,
                config=config,
                client=client,
                workdir=workdir,
                cache=cache,
            )
            old_tree = extract_archive(fetched.old.path, workdir / "extract-old", config.sandbox)
            new_tree = extract_archive(fetched.new.path, workdir / "extract-new", config.sandbox)
            cross_check_unpacked_size(
                old_tree.total_bytes, declared_unpacked_size(fetched.old.metadata)
            )
            cross_check_unpacked_size(
                new_tree.total_bytes, declared_unpacked_size(fetched.new.metadata)
            )
            ctx = build_diff_context(
                ecosystem=Ecosystem.NPM,
                package_name=pair.name,
                old_version=pair.old_version,
                new_version=pair.new_version,
                published_at=fetched.new.published_at,
                old=old_tree,
                new=new_tree,
                limits=config.sandbox,
                obfuscation=config.obfuscation,
                metadata_before=fetched.old.metadata,
                metadata_after=fetched.new.metadata,
            )
            try:
                active, _metadata, result, ignored_counts, baselined_findings = _active_findings(
                    ctx,
                    ignored_set,
                    config=config,
                    baseline_keys=baseline_keys,
                    experimental=experimental,
                )
            except _IncompleteAnalysis as exc:
                return _failed(pair, ANALYSIS_INCOMPLETE, parse_problems=exc.parse_problems)
            return PairAnalysis(
                name=pair.name,
                old_version=pair.old_version,
                new_version=pair.new_version,
                findings=active,
                score=result.score,
                boosts=result.boosts,
                digests=(fetched.old.digest_method, fetched.new.digest_method),
                files=_counts(ctx.changes),
                ignored=ignored_counts,
                baselined=len(baselined_findings),
                acknowledged=active + baselined_findings,
            )
    except FetchError as exc:
        return _failed(pair, exc.code.value)
    except ArchiveRejected as exc:
        return _failed(pair, exc.rejection.reason_code.value)
    except Exception:
        return _failed(pair, INTERNAL_ERROR)


def _failed(pair: ChangedPair, code: str, *, parse_problems: Sequence[str] = ()) -> PairAnalysis:
    return PairAnalysis(
        name=pair.name,
        old_version=pair.old_version,
        new_version=pair.new_version,
        error=code,
        parse_problems=tuple(parse_problems),
    )


class _IncompleteAnalysis(Exception):
    """The rules could not see enough of the package; carries stable parse-problem kinds."""

    def __init__(self, parse_problems: tuple[str, ...]) -> None:
        super().__init__(ANALYSIS_INCOMPLETE)
        self.parse_problems = parse_problems


def _active_findings(
    ctx: DiffContext,
    ignored_set: frozenset[str],
    *,
    config: Config,
    informational_families: frozenset[RuleFamily] = frozenset(),
    baseline_keys: frozenset[BaselineKey] = frozenset(),
    experimental: bool = False,
) -> tuple[
    tuple[Finding, ...],
    tuple[tuple[str, int], ...],
    ScoreResult,
    tuple[tuple[str, int], ...],
    tuple[Finding, ...],
]:
    """The one rule/score path shared by changed pairs and no-baseline new packages.

    Returns the scored findings, the per-rule counts of ``informational_families``
    findings, the score of the scored findings, the per-rule ignored counts, and the
    findings the baseline hid. Informational families still run, but are neither
    reported nor scored: for a brand-new package there is no baseline, so a family-4
    "change" against the empty tree describes what the package carries, not what
    changed (L2d). A ``baseline_keys`` match (SPEC §9.1 decision 16) hides a finding
    from the report and the score exactly like an ``--ignore``; the hidden findings
    are returned separately so ``--update-baseline`` and the counts can use them.
    """
    manifest_changes = diff_root_manifests(ctx)
    extra_errors = manifest_parse_errors(manifest_changes)
    if extra_errors:
        ctx = ctx.model_copy(
            update={
                "parse_errors": (*ctx.parse_errors, *extra_errors),
                "views_incomplete": True,
            }
        )

    findings = run_rules(ctx, experimental=experimental)
    if analysis_incomplete(findings):
        raise _IncompleteAnalysis(tuple(sorted({error.kind.value for error in ctx.parse_errors})))

    active = tuple(item for item in findings if item.rule_id not in ignored_set)
    families = families_by_rule_id()
    scored: list[Finding] = []
    informational: list[Finding] = []
    baselined: list[Finding] = []
    for item in active:
        if families.get(item.rule_id, frozenset()) & informational_families:
            informational.append(item)
        elif (
            ctx.package_name,
            item.rule_id,
            item.path,
            evidence_sha256(item.evidence),
        ) in baseline_keys:
            baselined.append(item)
        else:
            scored.append(item)
    scored_findings = tuple(scored)
    result = score(
        scored_findings,
        scoring=config.scoring,
        families=families,
        rule_set_version=rule_set_version(),
    )
    return (
        scored_findings,
        _rule_counts(informational),
        result,
        _ignored_counts(findings, ignored_set),
        tuple(baselined),
    )


def _analyse_new_packages(
    packages: Sequence[NewPackage],
    *,
    config: Config,
    client: HttpClient,
    ignored: Sequence[str],
    cache: DownloadCache | None,
    baseline_keys: frozenset[BaselineKey],
    experimental: bool = False,
) -> tuple[NewPackageAnalysis, ...]:
    if not packages:
        return ()
    workers = max(1, min(config.lock.concurrency, len(packages)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(
            pool.map(
                lambda package: _analyse_new_package(
                    package,
                    config=config,
                    client=client,
                    ignored=ignored,
                    cache=cache,
                    baseline_keys=baseline_keys,
                    experimental=experimental,
                ),
                packages,
            )
        )
    return tuple(sorted(results, key=lambda item: (item.name, item.version)))


def _analyse_new_package(
    package: NewPackage,
    *,
    config: Config,
    client: HttpClient,
    ignored: Sequence[str],
    cache: DownloadCache | None,
    baseline_keys: frozenset[BaselineKey],
    experimental: bool = False,
) -> NewPackageAnalysis:
    ignored_set = frozenset(ignored)
    try:
        with tempfile.TemporaryDirectory(prefix="pkgwatch-lock-") as temporary:
            workdir = Path(temporary)
            artifact = fetch_release(
                name=package.name,
                version=package.version,
                config=config,
                client=client,
                workdir=workdir,
                cache=cache,
            )
            new_tree = extract_archive(artifact.path, workdir / "extract-new", config.sandbox)
            cross_check_unpacked_size(
                new_tree.total_bytes, declared_unpacked_size(artifact.metadata)
            )
            ctx = build_diff_context(
                ecosystem=Ecosystem.NPM,
                package_name=package.name,
                old_version=NO_BASELINE_VERSION,
                new_version=package.version,
                published_at=artifact.published_at,
                old=_empty_tree(workdir / "extract-old"),
                new=new_tree,
                limits=config.sandbox,
                obfuscation=config.obfuscation,
                metadata_after=artifact.metadata,
            )
            try:
                active, informational, result, ignored_counts, baselined_findings = (
                    _active_findings(
                        ctx,
                        ignored_set,
                        config=config,
                        informational_families=frozenset({RuleFamily.METADATA}),
                        baseline_keys=baseline_keys,
                        experimental=experimental,
                    )
                )
            except _IncompleteAnalysis as exc:
                return _failed_new(package, ANALYSIS_INCOMPLETE, parse_problems=exc.parse_problems)
            return NewPackageAnalysis(
                name=package.name,
                version=package.version,
                findings=active,
                score=result.score,
                boosts=result.boosts,
                digest=artifact.digest_method,
                files=_counts(ctx.changes),
                informational=informational,
                ignored=ignored_counts,
                baselined=len(baselined_findings),
                acknowledged=active + baselined_findings,
            )
    except FetchError as exc:
        return _failed_new(package, exc.code.value)
    except ArchiveRejected as exc:
        return _failed_new(package, exc.rejection.reason_code.value)
    except Exception:
        return _failed_new(package, INTERNAL_ERROR)


def _empty_tree(root: Path) -> ExtractionResult:
    """No predecessor archive exists; the hash of no bytes is its honest identity."""
    return ExtractionResult(
        archive_sha256=hashlib.sha256(b"").hexdigest(),
        archive_format=ArchiveFormat.TAR_GZ,
        root=root,
        file_count=0,
        total_bytes=0,
        entries=(),
    )


def _failed_new(
    package: NewPackage, code: str, *, parse_problems: Sequence[str] = ()
) -> NewPackageAnalysis:
    return NewPackageAnalysis(
        name=package.name,
        version=package.version,
        error=code,
        parse_problems=tuple(parse_problems),
    )


def _counts(changes: Sequence[FileChange]) -> tuple[int, int, int]:
    return (
        sum(1 for item in changes if item.change_type is ChangeType.ADDED),
        sum(1 for item in changes if item.change_type is ChangeType.REMOVED),
        sum(1 for item in changes if item.change_type is ChangeType.MODIFIED),
    )


def _ignored_counts(
    findings: Sequence[Finding], ignored: frozenset[str]
) -> tuple[tuple[str, int], ...]:
    return _rule_counts([item for item in findings if item.rule_id in ignored])


def _rule_counts(findings: Sequence[Finding]) -> tuple[tuple[str, int], ...]:
    """Per-rule counts, sorted by rule_id."""
    counts: dict[str, int] = {}
    for item in findings:
        counts[item.rule_id] = counts.get(item.rule_id, 0) + 1
    return tuple(sorted(counts.items()))
