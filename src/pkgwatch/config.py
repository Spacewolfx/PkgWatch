"""Configuration loaded from TOML.

All defaults mirror SPEC.md; every limit is configurable because the sandbox caps are
deployment policy, not constants.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pkgwatch.models import Ecosystem, ObfuscationLimits, SandboxLimits, Severity

_STRICT = ConfigDict(extra="forbid", frozen=True)


class PathsConfig(BaseModel):
    model_config = _STRICT

    data_dir: Path = Path("data")
    db_path: Path = Path("data/pkgwatch.sqlite3")

    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def artifacts_dir(self) -> Path:
        return self.raw_dir / "artifacts"

    @property
    def extract_dir(self) -> Path:
        return self.raw_dir / "extract"

    @property
    def labels_dir(self) -> Path:
        return self.data_dir / "labels"

    @property
    def splits_dir(self) -> Path:
        return self.data_dir / "splits"


class EcosystemsConfig(BaseModel):
    model_config = _STRICT

    enabled: tuple[Ecosystem, ...] = (Ecosystem.NPM,)
    watchlist: dict[Ecosystem, tuple[str, ...]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _consistent(self) -> EcosystemsConfig:
        if not self.enabled:
            raise ValueError("at least one ecosystem must be enabled")
        if len(set(self.enabled)) != len(self.enabled):
            raise ValueError("enabled ecosystems must be unique")
        for ecosystem in self.watchlist:
            if ecosystem not in self.enabled:
                raise ValueError(f"watchlist for disabled ecosystem: {ecosystem}")
        return self


class SeverityWeights(BaseModel):
    model_config = _STRICT

    info: int = Field(default=0, ge=0)
    low: int = Field(default=4, ge=0)
    medium: int = Field(default=10, ge=0)
    high: int = Field(default=20, ge=0)
    critical: int = Field(default=35, ge=0)


class CorroborationWeights(BaseModel):
    model_config = _STRICT

    multi_capability: int = Field(default=10, ge=0)
    lifecycle_plus_capability: int = Field(default=20, ge=0)
    lifecycle_plus_obfuscation: int = Field(default=15, ge=0)


class DecayConfig(BaseModel):
    model_config = _STRICT

    instance_weights: tuple[float, ...] = (1.0, 0.5, 0.25)
    max_multiplier: float = Field(default=1.75, ge=1.0)

    @model_validator(mode="after")
    def _valid_weights(self) -> DecayConfig:
        if not self.instance_weights:
            raise ValueError("instance_weights must not be empty")
        if any(weight < 0 for weight in self.instance_weights):
            raise ValueError("instance_weights must be non-negative")
        if sum(self.instance_weights) > self.max_multiplier:
            raise ValueError("sum(instance_weights) must not exceed max_multiplier")
        return self


class ScoringConfig(BaseModel):
    model_config = _STRICT

    weights_version: str = Field(default="w1", min_length=1, max_length=32)
    alert_threshold: int = Field(default=40, ge=0, le=100)
    escalate_threshold: int = Field(default=70, ge=0, le=100)
    severity: SeverityWeights = Field(default_factory=SeverityWeights)
    corroboration: CorroborationWeights = Field(default_factory=CorroborationWeights)
    decay: DecayConfig = Field(default_factory=DecayConfig)

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> ScoringConfig:
        if self.alert_threshold > self.escalate_threshold:
            raise ValueError("alert_threshold must be <= escalate_threshold")
        return self


class ReproducibilityConfig(BaseModel):
    model_config = _STRICT

    seed: int = Field(default=1337, ge=0)
    split_salt: str = Field(default="pkgwatch-split-v1", min_length=1, max_length=64)


class FetchConfig(BaseModel):
    """Network limits for the v0.1 npm downloader (ARCHITECTURE §3, TB1/TB2).

    Every cap is a deployment policy, not a literal. ``max_metadata_bytes`` bounds the
    registry document (TB1: JSON is attacker-influenced), ``max_tarball_bytes`` bounds the
    artifact before it ever reaches the sandbox (TB2). Both are checked while streaming.
    """

    model_config = _STRICT

    max_metadata_bytes: int = Field(default=8 * 1024 * 1024, gt=0)
    max_tarball_bytes: int = Field(default=64 * 1024 * 1024, gt=0)
    request_timeout_seconds: float = Field(default=15.0, gt=0.0)
    max_redirects: int = Field(default=5, ge=0, le=10)
    # TODO(v0.1): SPEC §3 mentions a contact string in the crates.io User-Agent. The npm
    # registry's User-Agent policy and rate limits were not verified offline; no contact is
    # claimed here. Revisit before the first live-registry run.
    user_agent: str = Field(default="pkgwatch/0.1.0", min_length=1, max_length=128)
    # ``None`` means the operating system's user cache directory, never the repository.
    cache_dir: Path | None = None


class IgnoredRule(BaseModel):
    """One rule the operator has decided not to hear about — with the reason why (L3).

    The reason is mandatory: config ignores are policy, and an unexplained suppression is
    the silent failure this tool exists to prevent."""

    model_config = _STRICT

    rule: str = Field(min_length=1, max_length=96)
    reason: str = Field(min_length=1, max_length=1024)


class LockConfig(BaseModel):
    """Limits and policy for ``pkgwatch lock`` (SPEC §9.1, operator decision 2026-11-07)."""

    model_config = _STRICT

    max_pairs: int = Field(default=300, gt=0)
    fail_on: Severity = Severity.MEDIUM
    ignored: tuple[IgnoredRule, ...] = Field(default_factory=tuple)
    concurrency: int = Field(default=4, gt=0)
    max_lockfile_bytes: int = Field(default=20 * 1024 * 1024, gt=0)
    max_json_depth: int = Field(default=64, gt=0)
    # ``None`` means the operating system's user cache directory, never the repository.
    cache_dir: Path | None = None
    max_attempts: int = Field(default=3, ge=1, le=10)
    retry_base_delay_seconds: float = Field(default=0.5, gt=0.0)
    retry_max_delay_seconds: float = Field(default=8.0, gt=0.0)
    request_delay_seconds: float = Field(default=0.1, ge=0.0)

    @model_validator(mode="after")
    def _ordered_delays(self) -> LockConfig:
        if self.retry_base_delay_seconds > self.retry_max_delay_seconds:
            raise ValueError("retry_base_delay_seconds must be <= retry_max_delay_seconds")
        return self


class Config(BaseModel):
    model_config = _STRICT

    config_version: int = 1
    paths: PathsConfig = Field(default_factory=PathsConfig)
    sandbox: SandboxLimits = Field(default_factory=SandboxLimits)
    ecosystems: EcosystemsConfig = Field(default_factory=EcosystemsConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    reproducibility: ReproducibilityConfig = Field(default_factory=ReproducibilityConfig)
    fetch: FetchConfig = Field(default_factory=FetchConfig)
    lock: LockConfig = Field(default_factory=LockConfig)
    # SPEC §6.5.1 — operator decision 2026-11-07, initial untuned values, not measured.
    obfuscation: ObfuscationLimits = Field(default_factory=ObfuscationLimits)

    @classmethod
    def load(cls, path: Path) -> Config:
        """Load TOML, resolving relative paths against the config file's directory."""
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
        config = cls.model_validate(raw)
        base = path.resolve().parent
        lock = config.lock
        if lock.cache_dir is not None and not lock.cache_dir.is_absolute():
            lock = lock.model_copy(update={"cache_dir": _resolve(base, lock.cache_dir)})
        fetch = config.fetch
        if fetch.cache_dir is not None and not fetch.cache_dir.is_absolute():
            fetch = fetch.model_copy(update={"cache_dir": _resolve(base, fetch.cache_dir)})
        return config.model_copy(
            update={
                "paths": PathsConfig(
                    data_dir=_resolve(base, config.paths.data_dir),
                    db_path=_resolve(base, config.paths.db_path),
                ),
                "lock": lock,
                "fetch": fetch,
            }
        )

    @classmethod
    def from_toml(cls, text: str) -> Config:
        return cls.model_validate(tomllib.loads(text))

    @classmethod
    def write_default(cls, path: Path, *, overwrite: bool = False) -> None:
        if path.exists() and not overwrite:
            raise FileExistsError(str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(DEFAULT_TOML, encoding="utf-8")


def _resolve(base: Path, value: Path) -> Path:
    return value if value.is_absolute() else (base / value)


DEFAULT_TOML = """\
# pkgwatch configuration. Relative paths resolve against this file's directory.

config_version = 1

[paths]
data_dir = "data"
db_path = "data/pkgwatch.sqlite3"

[sandbox]
max_artifact_bytes = 67108864
max_total_uncompressed_bytes = 83886080
max_single_file_bytes = 16777216
max_file_count = 5000
max_entry_depth = 32
max_entry_path_len = 512
max_compression_ratio = 200.0
extract_deadline_seconds = 60.0
max_nesting_archives = 0
text_scan_bytes = 2097152

[ecosystems]
enabled = ["npm"]

[ecosystems.watchlist]

[scoring]
weights_version = "w1"
alert_threshold = 40
escalate_threshold = 70

[scoring.severity]
info = 0
low = 4
medium = 10
high = 20
critical = 35

[scoring.corroboration]
multi_capability = 10
lifecycle_plus_capability = 20
lifecycle_plus_obfuscation = 15

[scoring.decay]
instance_weights = [1.0, 0.5, 0.25]
max_multiplier = 1.75

[reproducibility]
seed = 1337
split_salt = "pkgwatch-split-v1"

[fetch]
max_metadata_bytes = 8388608
max_tarball_bytes = 67108864
request_timeout_seconds = 15.0
max_redirects = 5
user_agent = "pkgwatch/0.1.0"
# cache_dir: omit to use the user cache directory (never the repository)

[lock]
max_pairs = 300
fail_on = "medium"
# ignored rules need a reason: ignored = [{rule = "RULE_ID", reason = "why"}]
ignored = []
concurrency = 4
max_lockfile_bytes = 20971520
max_json_depth = 64
# cache_dir: omit to use the user cache directory (never the repository)
max_attempts = 3
retry_base_delay_seconds = 0.5
retry_max_delay_seconds = 8.0
request_delay_seconds = 0.1

[obfuscation]
min_blob_length = 200
entropy_min_length = 64
entropy_threshold_bits = 4.5
min_escapes_per_line = 20
"""


def dump_manifest(config: Config) -> dict[str, Any]:
    """Resolved config for a run manifest (SPEC §8)."""
    return config.model_dump(mode="json")
