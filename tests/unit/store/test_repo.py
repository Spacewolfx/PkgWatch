"""Repository round-trips for the three M2 tables.

The repository is the only place SQL lives, and its interface is what M3 extends, so
these tests pin identity, ordering, and the no-implicit-clock rule.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pkgwatch.models import Ecosystem, ReleaseStatus, RunRecord, WatchEntry
from pkgwatch.store.db import connect, migrate
from pkgwatch.store.repo import Repository
from tests.support.records import make_release

T0 = datetime(2026, 11, 5, 12, 0, tzinfo=UTC)
T1 = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
T2 = datetime(2026, 11, 6, 8, 15, tzinfo=UTC)


def _opened(path: Path) -> sqlite3.Connection:
    """A migrated connection: connect() opens, migrate() builds, and callers say which they want."""
    connection = connect(path)
    migrate(connection)
    return connection


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[Repository]:
    connection = _opened(tmp_path / "pkg.sqlite3")
    yield Repository(connection)
    connection.close()


def _run(**overrides: object) -> RunRecord:
    values: dict[str, object] = {
        "run_id": "2026-11-05T120000Z-deadbeef",
        "started_at": T0,
        "finished_at": None,
        "manifest_path": "runs/2026-11-05T120000Z-deadbeef/manifest.json",
        "manifest": {"seed": 1337, "config": {"config_version": 1}},
        "rule_set_version": "0123456789ab",
        "weights_version": "w1",
        "schema_version": 1,
        "sqlite_user_version": 1,
    }
    values.update(overrides)
    return RunRecord.model_validate(values)


def test_release_round_trip_preserves_every_field(repo: Repository) -> None:
    release = make_release()
    repo.upsert_release(release)
    stored = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert stored is not None
    assert stored.release == release
    assert stored.status is ReleaseStatus.PENDING
    assert stored.analysis_incomplete is False
    assert stored.stage_error is None


def test_release_identity_is_ecosystem_name_version(repo: Repository) -> None:
    repo.upsert_release(make_release())
    repo.upsert_release(make_release(size=9999))
    repo.upsert_release(make_release(version="1.0.0"))
    repo.upsert_release(make_release(ecosystem=Ecosystem.PYPI, version="1.0.0"))
    assert len(repo.list_releases(Ecosystem.NPM, "demo-pkg")) == 2
    assert len(repo.list_releases(Ecosystem.PYPI, "demo-pkg")) == 1
    npm = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert npm is not None
    assert npm.release.size == 9999


def test_releases_are_listed_newest_published_first(repo: Repository) -> None:
    repo.upsert_release(make_release(version="1.0.0", published_at=T1))
    repo.upsert_release(make_release(version="1.1.0", published_at=T0))
    repo.upsert_release(make_release(version="1.2.0", published_at=T2))
    listed = repo.list_releases(Ecosystem.NPM, "demo-pkg")
    assert [item.release.version for item in listed] == ["1.2.0", "1.1.0", "1.0.0"]


def test_get_missing_release_returns_none(repo: Repository) -> None:
    assert repo.get_release(Ecosystem.CRATES, "nope", "0.1.0") is None


def test_status_advances_without_touching_other_columns(repo: Repository) -> None:
    release = make_release()
    repo.upsert_release(release, status=ReleaseStatus.PENDING)
    repo.set_status(Ecosystem.NPM, "demo-pkg", "1.1.0", ReleaseStatus.EXTRACTED)
    stored = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert stored is not None
    assert stored.status is ReleaseStatus.EXTRACTED
    assert stored.release == release


def test_stage_error_is_recorded_and_cleared(repo: Repository) -> None:
    repo.upsert_release(make_release())
    repo.set_status(Ecosystem.NPM, "demo-pkg", "1.1.0", ReleaseStatus.PENDING, stage_error="boom")
    stored = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert stored is not None
    assert stored.stage_error == "boom"

    repo.set_status(Ecosystem.NPM, "demo-pkg", "1.1.0", ReleaseStatus.FETCHED)
    cleared = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert cleared is not None
    assert cleared.stage_error is None


def test_long_stage_error_is_capped(repo: Repository) -> None:
    repo.upsert_release(make_release())
    repo.set_status(
        Ecosystem.NPM, "demo-pkg", "1.1.0", ReleaseStatus.PENDING, stage_error="x" * 5000
    )
    stored = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert stored is not None
    assert stored.stage_error is not None
    assert len(stored.stage_error) <= 500


def test_analysis_incomplete_flag_survives_status_changes(repo: Repository) -> None:
    repo.upsert_release(make_release())
    repo.set_analysis_incomplete(Ecosystem.NPM, "demo-pkg", "1.1.0", True)
    repo.set_status(Ecosystem.NPM, "demo-pkg", "1.1.0", ReleaseStatus.SCORED)
    stored = repo.get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert stored is not None
    assert stored.analysis_incomplete is True


def test_setting_status_on_unknown_release_raises(repo: Repository) -> None:
    with pytest.raises(KeyError, match="demo-pkg"):
        repo.set_status(Ecosystem.NPM, "demo-pkg", "9.9.9", ReleaseStatus.FETCHED)


def test_watchlist_round_trip_and_removal(repo: Repository) -> None:
    repo.add_watch(WatchEntry(ecosystem=Ecosystem.NPM, package_name="demo-pkg", added_at=T0))
    repo.add_watch(
        WatchEntry(ecosystem=Ecosystem.PYPI, package_name="other", added_at=T1, note="wheel-only")
    )
    assert [entry.package_name for entry in repo.list_watch()] == ["demo-pkg", "other"]
    assert [entry.package_name for entry in repo.list_watch(Ecosystem.PYPI)] == ["other"]

    repo.add_watch(
        WatchEntry(ecosystem=Ecosystem.NPM, package_name="demo-pkg", added_at=T2, note="bumped")
    )
    entries = repo.list_watch(Ecosystem.NPM)
    assert len(entries) == 1
    assert entries[0].note == "bumped"
    assert entries[0].added_at == T2

    assert repo.remove_watch(Ecosystem.NPM, "demo-pkg") is True
    assert repo.remove_watch(Ecosystem.NPM, "demo-pkg") is False


def test_watchlist_is_ordered_by_ecosystem_then_name(repo: Repository) -> None:
    for name in ("zeta", "alpha"):
        repo.add_watch(WatchEntry(ecosystem=Ecosystem.NPM, package_name=name, added_at=T0))
    repo.add_watch(WatchEntry(ecosystem=Ecosystem.CRATES, package_name="mid", added_at=T0))
    assert [(entry.ecosystem.value, entry.package_name) for entry in repo.list_watch()] == [
        ("crates", "mid"),
        ("npm", "alpha"),
        ("npm", "zeta"),
    ]


def test_run_round_trip_with_manifest(repo: Repository) -> None:
    repo.record_run(_run())
    stored = repo.get_run("2026-11-05T120000Z-deadbeef")
    assert stored is not None
    assert stored.manifest == {"seed": 1337, "config": {"config_version": 1}}
    assert stored.finished_at is None
    assert stored.sqlite_user_version == 1

    repo.finish_run("2026-11-05T120000Z-deadbeef", finished_at=T2)
    finished = repo.get_run("2026-11-05T120000Z-deadbeef")
    assert finished is not None
    assert finished.finished_at == T2


def test_duplicate_run_id_is_rejected(repo: Repository) -> None:
    repo.record_run(_run())
    with pytest.raises(sqlite3.IntegrityError):
        repo.record_run(_run(manifest={"seed": 2}))


def test_runs_are_listed_most_recent_first(repo: Repository) -> None:
    repo.record_run(_run(run_id="run-a", started_at=T0))
    repo.record_run(_run(run_id="run-b", started_at=T2))
    repo.record_run(_run(run_id="run-c", started_at=T1))
    assert [run.run_id for run in repo.list_runs()] == ["run-b", "run-a", "run-c"]
    assert [run.run_id for run in repo.list_runs(limit=2)] == ["run-b", "run-a"]


def test_rows_persist_across_reopen(tmp_path: Path) -> None:
    first = _opened(tmp_path / "persist.sqlite3")
    Repository(first).upsert_release(make_release())
    first.close()

    second = _opened(tmp_path / "persist.sqlite3")
    stored = Repository(second).get_release(Ecosystem.NPM, "demo-pkg", "1.1.0")
    assert stored is not None
    assert stored.release.sha256 == "b" * 64
    second.close()
