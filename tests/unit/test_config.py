from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from pkgwatch.config import DEFAULT_TOML, Config
from pkgwatch.models import Severity


def test_defaults_match_spec() -> None:
    config = Config()
    assert config.sandbox.max_file_count == 5000
    assert config.sandbox.max_entry_depth == 32
    assert config.sandbox.max_compression_ratio == 200.0
    assert config.scoring.alert_threshold == 40
    assert config.scoring.escalate_threshold == 70
    assert config.scoring.severity.critical == 35
    assert config.scoring.decay.max_multiplier == 1.75
    assert config.reproducibility.split_salt == "pkgwatch-split-v1"


def test_default_toml_round_trips() -> None:
    from_toml = Config.from_toml(DEFAULT_TOML)
    assert from_toml.model_dump() == Config().model_dump()


def test_load_resolves_relative_paths(tmp_path: Path) -> None:
    path = tmp_path / "pkgwatch.toml"
    path.write_text(
        '[paths]\ndata_dir = "assets"\ndb_path = "assets/db.sqlite3"\n',
        encoding="utf-8",
    )
    config = Config.load(path)
    assert config.paths.data_dir == tmp_path / "assets"
    assert config.paths.db_path == tmp_path / "assets" / "db.sqlite3"
    assert config.paths.raw_dir == tmp_path / "assets" / "raw"
    assert config.paths.labels_dir == tmp_path / "assets" / "labels"


def test_partial_override_keeps_defaults(tmp_path: Path) -> None:
    path = tmp_path / "pkgwatch.toml"
    path.write_text("[sandbox]\nmax_file_count = 7\n", encoding="utf-8")
    config = Config.load(path)
    assert config.sandbox.max_file_count == 7
    assert config.sandbox.max_entry_depth == 32


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Config.from_toml("[sandbox]\nmax_file_count = 7\nsurprise = 1\n")


def test_the_only_supported_config_version_is_one() -> None:
    assert Config().config_version == 1
    assert Config.from_toml("config_version = 1\n").config_version == 1


def test_an_unknown_config_version_is_rejected() -> None:
    with pytest.raises(ValidationError, match="config_version"):
        Config.from_toml("config_version = 2\n")
    with pytest.raises(ValidationError, match="config_version"):
        Config.from_toml("config_version = 0\n")


def test_thresholds_must_be_ordered() -> None:
    with pytest.raises(ValidationError, match="alert_threshold"):
        Config.from_toml("[scoring]\nalert_threshold = 80\nescalate_threshold = 50\n")


def test_watchlist_requires_enabled_ecosystem() -> None:
    with pytest.raises(ValidationError, match="disabled ecosystem"):
        Config.from_toml(
            '[ecosystems]\nenabled = ["npm"]\n[ecosystems.watchlist]\npypi = ["requests"]\n'
        )


def test_obfuscation_defaults_match_spec_6_5_1() -> None:
    from_toml = Config.from_toml(DEFAULT_TOML)
    assert from_toml.obfuscation.min_blob_length == 200
    assert from_toml.obfuscation.entropy_min_length == 64
    assert from_toml.obfuscation.entropy_threshold_bits == 4.5
    assert from_toml.obfuscation.min_escapes_per_line == 20
    assert from_toml.obfuscation.model_dump() == Config().obfuscation.model_dump()


def test_lock_defaults_match_spec_9_1() -> None:
    config = Config.from_toml(DEFAULT_TOML)

    assert config.lock.max_pairs == 300
    assert config.lock.concurrency == 4
    assert config.lock.max_lockfile_bytes == 20 * 1024 * 1024
    assert config.lock.max_json_depth == 64


def test_partial_lock_override_keeps_defaults() -> None:
    config = Config.from_toml("[lock]\nmax_pairs = 7\n")

    assert config.lock.max_pairs == 7
    assert config.lock.concurrency == 4


def test_write_default_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "pkgwatch.toml"
    Config.write_default(path)
    with pytest.raises(FileExistsError):
        Config.write_default(path)
    Config.write_default(path, overwrite=True)
    assert Config.load(path).sandbox.max_file_count == 5000


def test_lock_policy_defaults_to_medium_fail_on_and_no_ignores() -> None:
    config = Config()

    assert config.lock.fail_on is Severity.MEDIUM
    assert config.lock.ignored == ()


def test_lock_policy_from_toml() -> None:
    config = Config.from_toml(
        '[lock]\nfail_on = "high"\n'
        'ignored = [{rule = "DEPENDENCY_ADDED", reason = "accepted risk"}]\n'
    )

    assert config.lock.fail_on is Severity.HIGH
    assert tuple(item.rule for item in config.lock.ignored) == ("DEPENDENCY_ADDED",)
    assert config.lock.ignored[0].reason == "accepted risk"


def test_an_ignore_without_a_reason_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Config.from_toml('[lock]\nignored = [{rule = "DEPENDENCY_ADDED"}]\n')


def test_an_ignore_with_an_empty_reason_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Config.from_toml('[lock]\nignored = [{rule = "DEPENDENCY_ADDED", reason = ""}]\n')


def test_an_unknown_fail_on_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Config.from_toml('[lock]\nfail_on = "sometimes"\n')


def test_fetch_cache_dir_defaults_to_none() -> None:
    assert Config().fetch.cache_dir is None


def test_load_resolves_relative_fetch_cache_dir(tmp_path: Path) -> None:
    path = tmp_path / "pkgwatch.toml"
    path.write_text('[fetch]\ncache_dir = "downloads"\n', encoding="utf-8")
    config = Config.load(path)
    assert config.fetch.cache_dir == tmp_path / "downloads"
