"""The repository: the only place in pkgwatch that spells SQL against the release store.

M3 extends this interface rather than rewriting it, so the shapes here are deliberate:
release identity is ``(ecosystem, package_name, version)``, timestamps are stored as UTC
ISO-8601 so lexical order equals chronological order, and every read re-validates through
the pydantic records instead of handing back loose row tuples.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import Any

from pkgwatch.models import (
    STAGE_ERROR_MAX_CHARS,
    Ecosystem,
    Release,
    ReleaseStatus,
    RunRecord,
    StoredRelease,
    WatchEntry,
)

Row = dict[str, Any]


def _as_rows(cursor: sqlite3.Cursor) -> list[Row]:
    """Rows as name-keyed dicts, so a column added by a later migration cannot shift a read."""
    names = [column[0] for column in (cursor.description or ())]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def _parse(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def _cap(value: str | None) -> str | None:
    if value is None or len(value) <= STAGE_ERROR_MAX_CHARS:
        return value
    return value[: STAGE_ERROR_MAX_CHARS - 1] + "…"


class Repository:
    """Row gateway for ``releases``, ``watchlist`` and ``runs``."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection

    # -- releases ---------------------------------------------------------------

    def upsert_release(
        self, release: Release, *, status: ReleaseStatus = ReleaseStatus.PENDING
    ) -> None:
        """Insert a release, or refresh its registry data without rolling back its stage."""
        self._conn.execute(
            """
            INSERT INTO releases (
                ecosystem, package_name, version, published_at, previous_version,
                previous_published_at, tarball_url, sha256, size, registry_snapshot,
                source_endpoint, retracted, status, stage_error, analysis_incomplete
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)
            ON CONFLICT (ecosystem, package_name, version) DO UPDATE SET
                published_at = excluded.published_at,
                previous_version = excluded.previous_version,
                previous_published_at = excluded.previous_published_at,
                tarball_url = excluded.tarball_url,
                sha256 = excluded.sha256,
                size = excluded.size,
                registry_snapshot = excluded.registry_snapshot,
                source_endpoint = excluded.source_endpoint,
                retracted = excluded.retracted
            """,
            (
                release.ecosystem.value,
                release.package_name,
                release.version,
                _iso(release.published_at),
                release.previous_version,
                None
                if release.previous_published_at is None
                else _iso(release.previous_published_at),
                release.tarball_url,
                release.sha256,
                release.size,
                json.dumps(release.registry_snapshot, sort_keys=True, separators=(",", ":")),
                release.source_endpoint,
                int(release.retracted),
                status.value,
            ),
        )

    def get_release(
        self, ecosystem: Ecosystem, package_name: str, version: str
    ) -> StoredRelease | None:
        rows = _as_rows(
            self._conn.execute(
                "SELECT * FROM releases WHERE ecosystem = ? AND package_name = ? AND version = ?",
                (ecosystem.value, package_name, version),
            )
        )
        return None if not rows else _stored_release(rows[0])

    def list_releases(self, ecosystem: Ecosystem, package_name: str) -> tuple[StoredRelease, ...]:
        """Every stored version of a package, newest ``published_at`` first."""
        rows = _as_rows(
            self._conn.execute(
                """
                SELECT * FROM releases WHERE ecosystem = ? AND package_name = ?
                ORDER BY published_at DESC, version DESC
                """,
                (ecosystem.value, package_name),
            )
        )
        return tuple(_stored_release(row) for row in rows)

    def set_status(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        version: str,
        status: ReleaseStatus,
        *,
        stage_error: str | None = None,
    ) -> None:
        """Advance a release. Omitting ``stage_error`` clears it."""
        cursor = self._conn.execute(
            "UPDATE releases SET status = ?, stage_error = ? "
            "WHERE ecosystem = ? AND package_name = ? AND version = ?",
            (status.value, _cap(stage_error), ecosystem.value, package_name, version),
        )
        if cursor.rowcount == 0:
            raise KeyError(f"no release for {ecosystem.value}/{package_name}@{version}")

    def set_analysis_incomplete(
        self, ecosystem: Ecosystem, package_name: str, version: str, value: bool
    ) -> None:
        cursor = self._conn.execute(
            "UPDATE releases SET analysis_incomplete = ? "
            "WHERE ecosystem = ? AND package_name = ? AND version = ?",
            (int(value), ecosystem.value, package_name, version),
        )
        if cursor.rowcount == 0:
            raise KeyError(f"no release for {ecosystem.value}/{package_name}@{version}")

    # -- watchlist --------------------------------------------------------------

    def add_watch(self, entry: WatchEntry) -> None:
        """Re-adding a package refreshes ``added_at`` and ``note``; it never duplicates a row."""
        self._conn.execute(
            """
            INSERT INTO watchlist (ecosystem, package_name, added_at, note) VALUES (?, ?, ?, ?)
            ON CONFLICT (ecosystem, package_name) DO UPDATE SET
                added_at = excluded.added_at, note = excluded.note
            """,
            (entry.ecosystem.value, entry.package_name, _iso(entry.added_at), entry.note),
        )

    def remove_watch(self, ecosystem: Ecosystem, package_name: str) -> bool:
        cursor = self._conn.execute(
            "DELETE FROM watchlist WHERE ecosystem = ? AND package_name = ?",
            (ecosystem.value, package_name),
        )
        return cursor.rowcount > 0

    def list_watch(self, ecosystem: Ecosystem | None = None) -> tuple[WatchEntry, ...]:
        columns = "SELECT ecosystem, package_name, added_at, note FROM watchlist"
        order = " ORDER BY ecosystem, package_name"
        if ecosystem is None:
            cursor = self._conn.execute(columns + order)
        else:
            cursor = self._conn.execute(
                columns + " WHERE ecosystem = ?" + order, (ecosystem.value,)
            )
        return tuple(
            WatchEntry(
                ecosystem=Ecosystem(row["ecosystem"]),
                package_name=row["package_name"],
                added_at=datetime.fromisoformat(row["added_at"]),
                note=row["note"],
            )
            for row in _as_rows(cursor)
        )

    # -- runs -------------------------------------------------------------------

    def record_run(self, run: RunRecord) -> None:
        self._conn.execute(
            """
            INSERT INTO runs (
                run_id, started_at, finished_at, manifest_path, manifest,
                rule_set_version, weights_version, schema_version, sqlite_user_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.run_id,
                _iso(run.started_at),
                None if run.finished_at is None else _iso(run.finished_at),
                run.manifest_path,
                json.dumps(run.manifest, sort_keys=True, separators=(",", ":")),
                run.rule_set_version,
                run.weights_version,
                run.schema_version,
                run.sqlite_user_version,
            ),
        )

    def finish_run(self, run_id: str, *, finished_at: datetime) -> None:
        cursor = self._conn.execute(
            "UPDATE runs SET finished_at = ? WHERE run_id = ?",
            (_iso(finished_at), run_id),
        )
        if cursor.rowcount == 0:
            raise KeyError(f"no run {run_id}")

    def get_run(self, run_id: str) -> RunRecord | None:
        rows = _as_rows(self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)))
        return None if not rows else _run_record(rows[0])

    def list_runs(self, limit: int | None = None) -> tuple[RunRecord, ...]:
        sql = "SELECT * FROM runs ORDER BY started_at DESC, run_id DESC"
        if limit is not None:
            sql += " LIMIT ?"
        cursor = self._conn.execute(sql, () if limit is None else (int(limit),))
        return tuple(_run_record(row) for row in _as_rows(cursor))


def _stored_release(row: Row) -> StoredRelease:
    previous_published_at = _parse(row["previous_published_at"])
    release = Release(
        ecosystem=Ecosystem(row["ecosystem"]),
        package_name=row["package_name"],
        version=row["version"],
        published_at=datetime.fromisoformat(row["published_at"]),
        previous_version=row["previous_version"],
        previous_published_at=previous_published_at,
        tarball_url=row["tarball_url"],
        sha256=row["sha256"],
        size=row["size"],
        registry_snapshot=json.loads(row["registry_snapshot"]),
        source_endpoint=row["source_endpoint"],
        retracted=bool(row["retracted"]),
    )
    return StoredRelease(
        release=release,
        status=ReleaseStatus(row["status"]),
        stage_error=row["stage_error"],
        analysis_incomplete=bool(row["analysis_incomplete"]),
    )


def _run_record(row: Row) -> RunRecord:
    return RunRecord(
        run_id=row["run_id"],
        started_at=datetime.fromisoformat(row["started_at"]),
        finished_at=_parse(row["finished_at"]),
        manifest_path=row["manifest_path"],
        manifest=json.loads(row["manifest"]),
        rule_set_version=row["rule_set_version"],
        weights_version=row["weights_version"],
        schema_version=row["schema_version"],
        sqlite_user_version=row["sqlite_user_version"],
    )
