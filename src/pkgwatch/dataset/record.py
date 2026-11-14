"""Turn one analysed pair into a hashed, atomic JSON record."""

from __future__ import annotations

import contextlib
import hashlib
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pkgwatch.config import Config
from pkgwatch.dataset.canonical import digest_of
from pkgwatch.dataset.errors import DatasetError
from pkgwatch.features import build_features
from pkgwatch.models import AnalysisRecord, DatasetFinding, DiffContext, Finding
from pkgwatch.rules import families_by_rule_id, rule_set_version
from pkgwatch.rules.runner import analysis_incomplete
from pkgwatch.score.engine import score


@dataclass(frozen=True)
class RecordOutcome:
    written: bool
    reason: str


def record_filename(ecosystem: str, package_name: str, old_version: str, new_version: str) -> str:
    identity = f"{ecosystem}|{package_name}|{old_version}|{new_version}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest() + ".json"


def record_pair(
    *,
    ctx: DiffContext,
    findings: Sequence[Finding],
    old_path: Path | None,
    new_path: Path,
    config: Config,
    experimental: bool,
    directory: Path,
) -> RecordOutcome:
    if old_path is None:
        return RecordOutcome(written=False, reason="new_package")

    try:
        directory.mkdir(parents=True, exist_ok=True)
        old_digest = hashlib.sha256(old_path.read_bytes()).hexdigest()
        new_digest = hashlib.sha256(new_path.read_bytes()).hexdigest()
    except OSError:
        raise DatasetError("RECORD_WRITE_FAILED") from None

    result = score(
        tuple(findings),
        scoring=config.scoring,
        families=families_by_rule_id(),
        rule_set_version=rule_set_version(),
    )
    record = AnalysisRecord(
        ecosystem=ctx.ecosystem,
        package_name=ctx.package_name,
        old_version=ctx.old_version,
        new_version=ctx.new_version,
        published_at=ctx.published_at,
        features=build_features(ctx, findings, result),
        findings=tuple(
            DatasetFinding(
                rule_id=item.rule_id, rule_version=item.rule_version, severity=item.severity
            )
            for item in findings
        ),
        rule_score=result.score,
        rule_set_version=result.rule_set_version,
        weights_version=result.weights_version,
        artifact_sha256_old=old_digest,
        artifact_sha256_new=new_digest,
        analysis_incomplete=analysis_incomplete(findings),
        config_sha256=digest_of(config.model_dump(mode="json")),
        experimental=experimental,
    )

    target = directory / record_filename(
        ctx.ecosystem.value, ctx.package_name, ctx.old_version, ctx.new_version
    )
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=directory, delete=False, encoding="utf-8"
        ) as handle:
            temporary = handle.name
            handle.write(record.model_dump_json())
            handle.write("\n")
        os.replace(temporary, target)
    except OSError:
        if temporary is not None:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
        raise DatasetError("RECORD_WRITE_FAILED") from None
    return RecordOutcome(written=True, reason="")
