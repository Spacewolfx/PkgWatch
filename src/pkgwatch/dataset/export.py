"""Export analysed records as a label-joined, split-assigned, manifest-pinned JSONL.

The exporter is the only place where a label decision is attached to an analysis. It reads
record files written by the CLI seams, never a database, and it never touches the network:
advisory labels are operator-supplied local JSON. Nothing here reads the clock: the run
id is derived from the manifest digest alone, so identical inputs collide deterministically
instead of producing near-duplicate datasets seconds apart.
"""

from __future__ import annotations

import dataclasses
import importlib.metadata
import sys
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from pkgwatch.dataset.canonical import canonical_json, digest_of
from pkgwatch.dataset.errors import DatasetError
from pkgwatch.dataset.split import SPLIT_SALT, TRAIN_MAX, VAL_MAX, assign_split
from pkgwatch.features import FEATURE_NAMES
from pkgwatch.labeling import load_advisories, load_human_labels, resolve_label
from pkgwatch.models import (
    SCHEMA_VERSION,
    AnalysisRecord,
    DatasetRecord,
    Label,
    LabelSource,
    Split,
)

_HOMOGENEITY_FIELDS = (
    "schema_version",
    "rule_set_version",
    "weights_version",
    "config_sha256",
    "experimental",
)


@dataclass(frozen=True)
class ExportResult:
    run_id: str
    directory: Path
    record_count: int
    skipped_incomplete: int
    label_counts: dict[str, int]
    split_counts: dict[str, int]
    conflict_count: int


def export_dataset(
    *,
    records: Path,
    labels: Path,
    out: Path,
) -> ExportResult:
    """Join labels, assign splits and write ``<out>/<run_id>/``. Offline, always."""
    paths = sorted(records.glob("*.json"))
    if not paths:
        raise DatasetError("EXPORT_NO_RECORDS")

    analyses = [_load(path) for path in paths]
    _require_homogeneous(analyses)

    complete = sorted(
        (item for item in analyses if not item.analysis_incomplete),
        key=lambda item: (
            item.ecosystem.value,
            item.package_name,
            item.old_version,
            item.new_version,
        ),
    )
    skipped_incomplete = len(analyses) - len(complete)

    identities = [
        (item.ecosystem.value, item.package_name, item.old_version, item.new_version)
        for item in complete
    ]
    human = load_human_labels(labels / "human")
    advisory = load_advisories(labels / "advisories", identities)

    exported: list[DatasetRecord] = []
    conflicts: list[dict[str, Any]] = []
    for analysis in complete:
        decision = resolve_label(analysis, human, advisory)
        split = assign_split(analysis.ecosystem.value, analysis.package_name)
        weak_on_holdout = decision.source is LabelSource.RULE_DERIVED and split in {
            Split.VAL,
            Split.TEST,
        }
        metric_eligible = decision.metric_eligible and decision.label is not Label.UNKNOWN
        if weak_on_holdout:
            metric_eligible = False
        exported.append(
            DatasetRecord(
                ecosystem=analysis.ecosystem,
                package_name=analysis.package_name,
                old_version=analysis.old_version,
                new_version=analysis.new_version,
                published_at=analysis.published_at,
                features=analysis.features,
                findings=analysis.findings,
                rule_score=analysis.rule_score,
                schema_version=analysis.schema_version,
                rule_set_version=analysis.rule_set_version,
                weights_version=analysis.weights_version,
                artifact_sha256_old=analysis.artifact_sha256_old,
                artifact_sha256_new=analysis.artifact_sha256_new,
                analysis_incomplete=analysis.analysis_incomplete,
                label=decision.label,
                label_source=decision.source,
                label_confidence=decision.confidence,
                split=split,
                metric_eligible=metric_eligible,
                label_provenance=decision.provenance,
            )
        )
        conflicts.extend(dataclasses.asdict(item) for item in decision.conflicts)

    label_counts = {
        "by_source": _counts(
            exported, (item.value for item in LabelSource), lambda item: item.label_source.value
        ),
        "by_label": _counts(
            exported, (item.value for item in Label), lambda item: item.label.value
        ),
    }
    split_counts = _counts(exported, (item.value for item in Split), lambda item: item.split.value)

    manifest = _manifest(
        analyses=analyses,
        record_count=len(exported),
        skipped_incomplete=skipped_incomplete,
        label_counts=label_counts,
        split_counts=split_counts,
    )
    run_id = digest_of(manifest)[:16]
    target = out / run_id
    try:
        out.mkdir(parents=True, exist_ok=True)
        # Rely on mkdir() raising FileExistsError: exists()-then-mkdir() is a TOCTOU.
        target.mkdir()
        _write_jsonl(target / "dataset.jsonl", (item.model_dump_json() for item in exported))
        (target / "manifest.json").write_bytes(canonical_json(manifest) + b"\n")
        _write_jsonl(
            target / "label_conflicts.jsonl",
            (
                canonical_json(item).decode("utf-8")
                for item in sorted(conflicts, key=lambda item: item["identity"])
            ),
        )
    except FileExistsError:
        raise DatasetError("EXPORT_RUN_EXISTS") from None
    except OSError:
        raise DatasetError("RECORD_WRITE_FAILED") from None

    return ExportResult(
        run_id=run_id,
        directory=target,
        record_count=len(exported),
        skipped_incomplete=skipped_incomplete,
        label_counts=label_counts["by_label"],
        split_counts=split_counts,
        conflict_count=len(conflicts),
    )


def _load(path: Path) -> AnalysisRecord:
    try:
        return AnalysisRecord.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError):
        raise DatasetError("DATASET_RECORD_INVALID", detail=path.name) from None


def _require_homogeneous(analyses: Sequence[AnalysisRecord]) -> None:
    signatures = {tuple(getattr(item, name) for name in _HOMOGENEITY_FIELDS) for item in analyses}
    if len(signatures) != 1:
        raise DatasetError("DATASET_RECORD_INHOMOGENEOUS")


def _counts(
    records: Sequence[DatasetRecord],
    values: Iterable[str],
    key: Callable[[DatasetRecord], str],
) -> dict[str, int]:
    counted = Counter(key(item) for item in records)
    return {value: counted.get(value, 0) for value in values}


def _manifest(
    *,
    analyses: Sequence[AnalysisRecord],
    record_count: int,
    skipped_incomplete: int,
    label_counts: dict[str, dict[str, int]],
    split_counts: dict[str, int],
) -> dict[str, Any]:
    first = analyses[0]
    identities = sorted(
        [item.ecosystem.value, item.package_name, item.old_version, item.new_version]
        for item in analyses
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "rule_set_version": first.rule_set_version,
        "weights_version": first.weights_version,
        "config_sha256": first.config_sha256,
        "experimental": first.experimental,
        "split_salt": SPLIT_SALT,
        "split_thresholds": {"train_max": TRAIN_MAX, "val_max": VAL_MAX},
        "seeds": {},
        "toolchain": _toolchain(),
        "sqlite_user_version": None,
        "git_sha": _git_sha(),
        "record_count": record_count,
        # New packages are skipped at record time and never reach this directory, so the
        # exporter cannot observe them; null says "not tracked", never a false zero.
        "skipped": {"incomplete": skipped_incomplete, "new_package": None},
        "label_counts": label_counts,
        "split_counts": split_counts,
        "feature_catalog_sha256": digest_of(sorted(FEATURE_NAMES)),
        "records_sha256": digest_of(identities),
    }


def _toolchain() -> dict[str, str | None]:
    return {
        "python": sys.version.split()[0],
        "pkgwatch": _installed_version("pkgwatch"),
        "mypy": _installed_version("mypy"),
        "ruff": _installed_version("ruff"),
    }


def _installed_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _git_sha() -> str | None:
    """Read ``.git/HEAD`` and its ref file. Never an OS process (structural invariant)."""
    root = Path(__file__).resolve()
    for parent in root.parents:
        head = parent / ".git" / "HEAD"
        if not head.is_file():
            continue
        try:
            text = head.read_text(encoding="utf-8").strip()
            if not text.startswith("ref:"):
                return text or None
            ref = parent / ".git" / text.removeprefix("ref:").strip()
            return ref.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None
    return None


def _write_jsonl(path: Path, lines: Iterable[str]) -> None:
    body = "".join(f"{line}\n" for line in lines)
    path.write_text(body, encoding="utf-8")
