"""Pydantic records that cross module boundaries.

Every model is frozen and forbids unknown fields, so a new field is a deliberate
schema change and an accidental upstream key becomes a validation error instead of
silently entering the dataset.
"""

from __future__ import annotations

import hashlib
import math
import re
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = 1
EVIDENCE_MAX_CHARS = 200

_STRICT = ConfigDict(extra="forbid", frozen=True)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_FEATURE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FEATURE_CATEGORY_RE = re.compile(r"^[A-Za-z0-9_.:/*@+\-]{1,48}$")
_DETAIL_KEY_MAX = 64
_DETAIL_VALUE_MAX = 64


class Ecosystem(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    CRATES = "crates"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ChangeType(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    RENAMED = "renamed"
    UNCHANGED = "unchanged"
    BINARY = "binary"
    MODE_ONLY = "mode_only"
    NESTED_ARCHIVE = "nested_archive"


class FileRole(StrEnum):
    SOURCE = "source"
    MANIFEST = "manifest"
    LOCKFILE = "lockfile"
    TEST = "test"
    DOC = "doc"
    VENDOR = "vendor"
    BINARY = "binary"
    OTHER = "other"


class ArchiveFormat(StrEnum):
    TAR_GZ = "tar.gz"
    TAR = "tar"
    ZIP = "zip"


class ManifestKind(StrEnum):
    FILE = "file"
    DIR = "dir"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"
    NESTED_ARCHIVE = "nested_archive"


class RejectionCode(StrEnum):
    ARTIFACT_TOO_LARGE = "ARTIFACT_TOO_LARGE"
    TOTAL_UNCOMPRESSED_EXCEEDED = "TOTAL_UNCOMPRESSED_EXCEEDED"
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    FILE_COUNT_EXCEEDED = "FILE_COUNT_EXCEEDED"
    DEPTH_EXCEEDED = "DEPTH_EXCEEDED"
    PATH_TOO_LONG = "PATH_TOO_LONG"
    COMPRESSION_RATIO_EXCEEDED = "COMPRESSION_RATIO_EXCEEDED"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    ABSOLUTE_PATH = "ABSOLUTE_PATH"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    DRIVE_OR_UNC_PATH = "DRIVE_OR_UNC_PATH"
    BACKSLASH_IN_NAME = "BACKSLASH_IN_NAME"
    SYMLINK_OUTSIDE_TARGET = "SYMLINK_OUTSIDE_TARGET"
    SYMLINK_ABSOLUTE_TARGET = "SYMLINK_ABSOLUTE_TARGET"
    SYMLINK_TARGET_TOO_LONG = "SYMLINK_TARGET_TOO_LONG"
    HARDLINK_OUTSIDE_TARGET = "HARDLINK_OUTSIDE_TARGET"
    HARDLINK_MISSING_TARGET = "HARDLINK_MISSING_TARGET"
    HARDLINK_CYCLE = "HARDLINK_CYCLE"
    PARENT_IS_SYMLINK = "PARENT_IS_SYMLINK"
    DEVICE_OR_FIFO = "DEVICE_OR_FIFO"
    UNSUPPORTED_MEMBER_TYPE = "UNSUPPORTED_MEMBER_TYPE"
    CASE_COLLISION = "CASE_COLLISION"
    DUPLICATE_MEMBER = "DUPLICATE_MEMBER"
    PATH_CONFLICT = "PATH_CONFLICT"
    NAME_HAS_CONTROL_CHARS = "NAME_HAS_CONTROL_CHARS"
    WINDOWS_ILLEGAL_NAME = "WINDOWS_ILLEGAL_NAME"
    INVALID_NAME = "INVALID_NAME"
    ENCRYPTED_ENTRY = "ENCRYPTED_ENTRY"
    EXTRACTION_ROOT_ESCAPE = "EXTRACTION_ROOT_ESCAPE"
    ARCHIVE_TRUNCATED = "ARCHIVE_TRUNCATED"
    ARCHIVE_FORMAT_UNSUPPORTED = "ARCHIVE_FORMAT_UNSUPPORTED"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    LIMITS_DISAGREE_WITH_REGISTRY = "LIMITS_DISAGREE_WITH_REGISTRY"


class Label(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class LabelSource(StrEnum):
    HUMAN = "human"
    ADVISORY_DB = "advisory_db"
    RULE_DERIVED = "rule_derived"


class Split(StrEnum):
    TRAIN = "train"
    VAL = "val"
    TEST = "test"


class RuleFamily(StrEnum):
    """SPEC §4.5 families. The value is part of the score semantics: do not renumber."""

    LIFECYCLE_SCRIPTS = "lifecycle_scripts"
    DANGEROUS_CAPABILITY = "dangerous_capability"
    OBFUSCATION = "obfuscation"
    METADATA = "metadata"


class ReleaseStatus(StrEnum):
    """Pipeline stage of a stored release, in execution order."""

    PENDING = "pending"
    FETCHED = "fetched"
    EXTRACTED = "extracted"
    DIFFED = "diffed"
    SCORED = "scored"
    EXPORTED = "exported"


class DiffLineOp(StrEnum):
    ADD = "add"
    DEL = "del"
    CTX = "ctx"


class ParseErrorKind(StrEnum):
    READ = "read"
    DECODE = "decode"
    BUDGET = "budget"
    DIFF = "diff"
    # SPEC §4.5.1: a malformed root package.json is a parse problem, never a crash.
    MANIFEST = "manifest"


class SandboxLimits(BaseModel):
    """Hard caps applied while validating and extracting an archive."""

    model_config = _STRICT

    max_artifact_bytes: int = Field(default=64 * 1024 * 1024, gt=0)
    max_total_uncompressed_bytes: int = Field(default=80 * 1024 * 1024, gt=0)
    max_single_file_bytes: int = Field(default=16 * 1024 * 1024, gt=0)
    max_file_count: int = Field(default=5000, gt=0)
    max_entry_depth: int = Field(default=32, gt=0)
    max_entry_path_len: int = Field(default=512, gt=0)
    max_compression_ratio: float = Field(default=200.0, ge=1.0)
    extract_deadline_seconds: float = Field(default=60.0, gt=0.0)
    max_nesting_archives: int = Field(default=0, ge=0)
    text_scan_bytes: int = Field(default=2 * 1024 * 1024, gt=0)


class ObfuscationLimits(BaseModel):
    """Family-3 thresholds (SPEC §6.5.1), carried on DiffContext so rules stay pure.

    Operator decision 2026-11-07: initial untuned values, not measured.
    """

    model_config = _STRICT

    min_blob_length: int = Field(default=200, gt=0)
    entropy_min_length: int = Field(default=64, gt=0)
    entropy_threshold_bits: float = Field(default=4.5, gt=0.0)
    min_escapes_per_line: int = Field(default=20, gt=0)


def _validate_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("must be an absolute http(s) URL")
    return value


class Release(BaseModel):
    model_config = _STRICT

    ecosystem: Ecosystem
    package_name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=128)
    published_at: AwareDatetime
    previous_version: str | None = Field(default=None, max_length=128)
    previous_published_at: AwareDatetime | None = None
    tarball_url: str = Field(max_length=2048)
    sha256: str
    size: int = Field(ge=0)
    registry_snapshot: dict[str, Any] = Field(default_factory=dict)
    source_endpoint: str = Field(max_length=2048)
    retracted: bool = False

    @field_validator("tarball_url", "source_endpoint")
    @classmethod
    def _http_url(cls, value: str) -> str:
        return _validate_url(value)

    @field_validator("sha256")
    @classmethod
    def _sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("must be 64 lowercase hex characters")
        return value


class FileChange(BaseModel):
    model_config = _STRICT

    path_old: str | None = Field(default=None, max_length=1024)
    path_new: str | None = Field(default=None, max_length=1024)
    change_type: ChangeType
    size_old: int | None = Field(default=None, ge=0)
    size_new: int | None = Field(default=None, ge=0)
    sha256_old: str | None = None
    sha256_new: str | None = None
    lines_added: int = Field(default=0, ge=0)
    lines_removed: int = Field(default=0, ge=0)
    mode_new: int | None = Field(default=None, ge=0, le=0o7777)
    is_text: bool = True
    role: FileRole = FileRole.OTHER

    @field_validator("sha256_old", "sha256_new")
    @classmethod
    def _optional_sha256(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256_RE.fullmatch(value):
            raise ValueError("must be 64 lowercase hex characters")
        return value


class SandboxRejection(BaseModel):
    model_config = _STRICT

    reason_code: RejectionCode
    detail: str
    offending_path: str | None = None
    limit_name: str | None = Field(default=None, max_length=64)
    limit_value: int | float | None = None
    observed_value: int | float | None = None

    @field_validator("detail")
    @classmethod
    def _cap_detail(cls, value: str) -> str:
        if len(value) <= EVIDENCE_MAX_CHARS:
            return value
        return value[: EVIDENCE_MAX_CHARS - 1] + "\u2026"

    @field_validator("offending_path")
    @classmethod
    def _sanitise_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = "".join("?" if ord(ch) < 0x20 or ord(ch) == 0x7F else ch for ch in value)
        if len(cleaned) > EVIDENCE_MAX_CHARS:
            return cleaned[: EVIDENCE_MAX_CHARS - 1] + "\u2026"
        return cleaned


class ManifestEntry(BaseModel):
    model_config = _STRICT

    path: str = Field(min_length=1, max_length=1024)
    kind: ManifestKind
    size: int = Field(ge=0)
    mode: int = Field(ge=0, le=0o7777)
    sha256: str | None = None
    link_target: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def _link_target_consistency(self) -> ManifestEntry:
        needs_link = self.kind in {ManifestKind.SYMLINK, ManifestKind.HARDLINK}
        if needs_link and not self.link_target:
            raise ValueError(f"{self.kind} entries require link_target")
        if not needs_link and self.link_target is not None:
            raise ValueError(f"{self.kind} entries must not carry link_target")
        return self


class ExtractionResult(BaseModel):
    model_config = _STRICT

    archive_sha256: str
    archive_format: ArchiveFormat
    root: Path
    file_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    entries: tuple[ManifestEntry, ...]

    @field_validator("archive_sha256")
    @classmethod
    def _archive_sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("must be 64 lowercase hex characters")
        return value


class Finding(BaseModel):
    """One rule hit. ``evidence`` is hard-capped so source text cannot leak wholesale."""

    model_config = _STRICT

    rule_id: str = Field(min_length=1, max_length=96, pattern=r"^[A-Z][A-Z0-9_]*$")
    rule_version: int = Field(ge=1)
    severity: Severity
    path: str | None = Field(default=None, max_length=1024)
    evidence: str
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    ecosystem: Ecosystem
    package_name: str = Field(min_length=1, max_length=214)
    old_version: str = Field(min_length=1, max_length=128)
    new_version: str = Field(min_length=1, max_length=128)
    details: dict[str, str | int | float | bool] = Field(default_factory=dict)

    @field_validator("evidence")
    @classmethod
    def _cap_evidence(cls, value: str) -> str:
        if len(value) <= EVIDENCE_MAX_CHARS:
            return value
        return value[: EVIDENCE_MAX_CHARS - 1] + "\u2026"

    @field_validator("details")
    @classmethod
    def _small_details(cls, value: dict[str, str | int | float | bool]) -> dict[str, Any]:
        for key, item in value.items():
            if len(key) > _DETAIL_KEY_MAX:
                raise ValueError(f"detail key too long: {key[:32]!r}")
            if isinstance(item, str) and len(item) > _DETAIL_VALUE_MAX:
                raise ValueError(f"detail value too long for {key!r}")
        return value

    @model_validator(mode="after")
    def _line_range(self) -> Finding:
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("line_end must be >= line_start")
        return self

    @property
    def finding_uid(self) -> str:
        parts = (
            self.rule_id,
            str(self.rule_version),
            self.path or "",
            "" if self.line_start is None else str(self.line_start),
            "" if self.line_end is None else str(self.line_end),
            self.evidence,
        )
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


class ScoreContribution(BaseModel):
    model_config = _STRICT

    rule_id: str
    rule_version: int = Field(ge=1)
    base: int = Field(ge=0)
    count_weight: float = Field(ge=0.0)
    subtotal: float = Field(ge=0.0)


class ScoreBoost(BaseModel):
    """One applied corroboration boost, named exactly as ``config.ScoringConfig`` spells it."""

    model_config = _STRICT

    name: str = Field(min_length=1, max_length=48)
    points: int = Field(ge=0)


class ScoreResult(BaseModel):
    model_config = _STRICT

    score: int = Field(ge=0, le=100)
    rule_set_version: str
    weights_version: str
    contributing_findings: tuple[Finding, ...]
    breakdown: tuple[ScoreContribution, ...]
    boosts: tuple[ScoreBoost, ...] = ()


class DatasetFinding(BaseModel):
    model_config = _STRICT

    rule_id: str = Field(min_length=1, max_length=96, pattern=r"^[A-Z][A-Z0-9_]*$")
    rule_version: int = Field(ge=1)
    severity: Severity


FeatureValue = int | float | bool | str


class DatasetRecord(BaseModel):
    """One record per (ecosystem, package, old_version, new_version)."""

    model_config = _STRICT

    ecosystem: Ecosystem
    package_name: str = Field(min_length=1, max_length=214)
    old_version: str = Field(min_length=1, max_length=128)
    new_version: str = Field(min_length=1, max_length=128)
    published_at: AwareDatetime
    features: dict[str, FeatureValue]
    findings: tuple[DatasetFinding, ...]
    rule_score: int = Field(ge=0, le=100)
    label: Label
    label_source: LabelSource
    label_confidence: float = Field(ge=0.0, le=1.0)
    split: Split
    schema_version: int = SCHEMA_VERSION
    rule_set_version: str
    weights_version: str
    artifact_sha256_old: str
    artifact_sha256_new: str
    analysis_incomplete: bool = False
    metric_eligible: bool = True
    label_provenance: str | None = None

    @field_validator("features")
    @classmethod
    def _bounded_features(cls, value: dict[str, FeatureValue]) -> dict[str, FeatureValue]:
        for name, item in value.items():
            if not _FEATURE_NAME_RE.fullmatch(name):
                raise ValueError(f"invalid feature name: {name[:32]!r}")
            if isinstance(item, bool):
                continue
            if isinstance(item, int | float):
                if isinstance(item, float) and not math.isfinite(item):
                    raise ValueError(f"non-finite feature value for {name!r}")
                continue
            if isinstance(item, str):
                if not _FEATURE_CATEGORY_RE.fullmatch(item):
                    raise ValueError(
                        f"feature {name!r} looks like raw text; features must be numeric "
                        "or a bounded categorical token"
                    )
                continue
            raise ValueError(f"unsupported feature value type for {name!r}")
        return value

    @field_validator("artifact_sha256_old", "artifact_sha256_new")
    @classmethod
    def _artifact_sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("must be 64 lowercase hex characters")
        return value

    @model_validator(mode="before")
    @classmethod
    def _derive_metric_eligibility(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        source = data.get("label_source")
        split = data.get("split")
        source_value = getattr(source, "value", source)
        split_value = getattr(split, "value", split)
        weak_on_holdout = source_value == LabelSource.RULE_DERIVED and split_value in {
            Split.VAL.value,
            Split.TEST.value,
        }
        if weak_on_holdout:
            if data.get("metric_eligible") is True:
                raise ValueError("rule_derived labels are never metric-eligible on val/test")
            return {**data, "metric_eligible": False}
        return {"metric_eligible": True, **data}

    @model_validator(mode="after")
    def _label_policy(self) -> DatasetRecord:
        if self.label_source is LabelSource.RULE_DERIVED:
            if self.label not in {Label.BENIGN, Label.SUSPICIOUS}:
                raise ValueError("rule_derived labels may only be benign or suspicious")
            if abs(self.label_confidence - 0.3) > 1e-9:
                raise ValueError("rule_derived labels are fixed at confidence 0.3")
        if self.label_source is LabelSource.ADVISORY_DB and self.label not in {
            Label.MALICIOUS,
            Label.UNKNOWN,
        }:
            raise ValueError("advisory_db labels may only be malicious or unknown")
        return self


DIFF_LINE_MAX_CHARS = 1024
STAGE_ERROR_MAX_CHARS = 500


class DiffLine(BaseModel):
    """One line of the unified diff of a changed file, with 1-based numbers per side."""

    model_config = _STRICT

    op: DiffLineOp
    text: str = Field(max_length=DIFF_LINE_MAX_CHARS)
    line_old: int | None = Field(default=None, ge=1)
    line_new: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _op_and_numbers_agree(self) -> DiffLine:
        required: dict[DiffLineOp, tuple[str, ...]] = {
            DiffLineOp.ADD: ("line_new",),
            DiffLineOp.DEL: ("line_old",),
            DiffLineOp.CTX: ("line_old", "line_new"),
        }
        missing = [name for name in required[self.op] if getattr(self, name) is None]
        if missing:
            raise ValueError(f"{self.op} lines require {', '.join(missing)}")
        return self


class FileView(BaseModel):
    """Decoded text of one file on one side of the diff, with its changed-line index."""

    model_config = _STRICT

    path: str = Field(min_length=1, max_length=1024)
    content: str = ""
    is_text: bool = True
    size: int = Field(ge=0)
    sha256: str
    truncated: bool = False
    diff_lines: tuple[DiffLine, ...] = ()

    @field_validator("sha256")
    @classmethod
    def _sha256(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("must be 64 lowercase hex characters")
        return value

    @model_validator(mode="after")
    def _no_content_without_text(self) -> FileView:
        if not self.is_text and self.content:
            raise ValueError("a view with is_text=False may not carry content")
        return self


class ParseError(BaseModel):
    """A per-file analysis failure. Recorded, never raised — SPEC §4.4."""

    model_config = _STRICT

    path: str = Field(min_length=1, max_length=1024)
    kind: ParseErrorKind
    detail: str

    @field_validator("detail")
    @classmethod
    def _cap_detail(cls, value: str) -> str:
        if len(value) <= EVIDENCE_MAX_CHARS:
            return value
        return value[: EVIDENCE_MAX_CHARS - 1] + "…"


class DiffContext(BaseModel):
    """Everything a rule is allowed to see (SPEC §4.2). Built by ``diff/``, read by ``rules/``."""

    model_config = _STRICT

    ecosystem: Ecosystem
    package_name: str = Field(min_length=1, max_length=214)
    old_version: str = Field(min_length=1, max_length=128)
    new_version: str = Field(min_length=1, max_length=128)
    published_at: AwareDatetime
    changes: tuple[FileChange, ...]
    files_new: dict[str, FileView] = Field(default_factory=dict)
    files_old: dict[str, FileView] = Field(default_factory=dict)
    metadata_before: dict[str, Any] = Field(default_factory=dict)
    metadata_after: dict[str, Any] = Field(default_factory=dict)
    parse_errors: tuple[ParseError, ...] = ()
    limits: SandboxLimits
    obfuscation: ObfuscationLimits = Field(default_factory=ObfuscationLimits)
    views_incomplete: bool = False

    @model_validator(mode="after")
    def _views_are_indexed_by_changes(self) -> DiffContext:
        known = {
            path
            for change in self.changes
            for path in (change.path_old, change.path_new)
            if path is not None
        }
        for side, views in (("files_new", self.files_new), ("files_old", self.files_old)):
            for path, view in views.items():
                if path not in known:
                    raise ValueError(f"{side} entry {path!r} has no FileChange")
                if view.path != path:
                    raise ValueError(f"{side} key {path!r} disagrees with view path")
        return self


class StoredRelease(BaseModel):
    """A ``releases`` row: the registry record plus how far the pipeline got."""

    model_config = _STRICT

    release: Release
    status: ReleaseStatus = ReleaseStatus.PENDING
    stage_error: str | None = None
    analysis_incomplete: bool = False

    @field_validator("stage_error")
    @classmethod
    def _cap_stage_error(cls, value: str | None) -> str | None:
        if value is None or len(value) <= STAGE_ERROR_MAX_CHARS:
            return value
        return value[: STAGE_ERROR_MAX_CHARS - 1] + "…"


class WatchEntry(BaseModel):
    model_config = _STRICT

    ecosystem: Ecosystem
    package_name: str = Field(min_length=1, max_length=214)
    added_at: AwareDatetime
    note: str | None = Field(default=None, max_length=EVIDENCE_MAX_CHARS)


class RunRecord(BaseModel):
    """A ``runs`` row: the reproducibility manifest of one CLI invocation (SPEC §8)."""

    model_config = _STRICT

    run_id: str = Field(min_length=1, max_length=64)
    started_at: AwareDatetime
    finished_at: AwareDatetime | None = None
    manifest_path: str = Field(min_length=1, max_length=1024)
    manifest: dict[str, Any] = Field(default_factory=dict)
    rule_set_version: str = Field(min_length=1, max_length=64)
    weights_version: str = Field(min_length=1, max_length=32)
    schema_version: int = Field(ge=0)
    sqlite_user_version: int = Field(ge=0)
