"""Forward-only migration runner: an old database must never be silently corrupted."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from pkgwatch.models import SCHEMA_VERSION
from pkgwatch.store import db
from pkgwatch.store.db import Migration, current_version, migrate
from pkgwatch.store.schema import MIGRATIONS


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    connection = db.connect(tmp_path / "pkgwatch.sqlite3")
    yield connection
    connection.close()


def test_fresh_database_reaches_target_version(conn: sqlite3.Connection) -> None:
    migrate(conn)
    assert current_version(conn) == db.TARGET_VERSION
    assert db.schema_version(conn) == SCHEMA_VERSION


def test_migrate_is_idempotent(conn: sqlite3.Connection) -> None:
    migrate(conn)
    before = current_version(conn)
    migrate(conn)
    assert current_version(conn) == before


def test_all_migration_steps_are_listed(conn: sqlite3.Connection) -> None:
    versions = [step.version for step in MIGRATIONS]
    assert versions == sorted(versions)
    assert versions[0] == 1
    assert versions[-1] == db.TARGET_VERSION


def test_newer_database_than_code_is_refused(conn: sqlite3.Connection) -> None:
    migrate(conn)
    conn.execute("PRAGMA user_version = 999")
    conn.commit()
    with pytest.raises(db.SchemaTooNew, match="999"):
        migrate(conn)


def test_duplicate_migration_versions_are_rejected(conn: sqlite3.Connection) -> None:
    first = Migration(
        version=1,
        description="create a",
        statements=("CREATE TABLE a (id INTEGER PRIMARY KEY)",),
    )
    duplicate = Migration(
        version=1,
        description="create b",
        statements=("CREATE TABLE b (id INTEGER PRIMARY KEY)",),
    )
    with pytest.raises(ValueError, match="unique"):
        migrate(conn, migrations=(first, duplicate))


def test_empty_migrations_still_refuse_a_newer_database(conn: sqlite3.Connection) -> None:
    migrate(conn)
    conn.execute("PRAGMA user_version = 999")
    conn.commit()
    with pytest.raises(db.SchemaTooNew, match="999"):
        migrate(conn, migrations=())


def test_migrations_apply_in_order_and_keep_data(tmp_path: Path) -> None:
    connection = db.connect(tmp_path / "step.sqlite3")
    first = Migration(
        version=1,
        description="create widget",
        statements=("CREATE TABLE widget (id INTEGER PRIMARY KEY, label TEXT NOT NULL)",),
    )
    second = Migration(
        version=2,
        description="add column",
        statements=("ALTER TABLE widget ADD COLUMN size INTEGER NOT NULL DEFAULT 0",),
    )
    migrate(connection, migrations=(first, second))
    connection.execute("INSERT INTO widget (label) VALUES ('a')")
    connection.commit()

    migrate(connection, migrations=(first, second))
    rows = connection.execute("SELECT label, size FROM widget").fetchall()
    assert rows == [("a", 0)]
    assert current_version(connection) == 2
    connection.close()


def test_failed_migration_rolls_back_and_keeps_previous_schema(tmp_path: Path) -> None:
    connection = db.connect(tmp_path / "rollback.sqlite3")
    first = Migration(
        version=1,
        description="create gadget",
        statements=("CREATE TABLE gadget (id INTEGER PRIMARY KEY)",),
    )
    broken = Migration(
        version=2,
        description="boom",
        statements=(
            "CREATE TABLE part (id INTEGER PRIMARY KEY)",
            "CREATE TABLE gadget (id INTEGER PRIMARY KEY)",
        ),
    )

    migrate(connection, migrations=(first,))
    connection.execute("INSERT INTO gadget (id) VALUES (1)")
    connection.commit()

    with pytest.raises(db.MigrationFailed):
        migrate(connection, migrations=(first, broken))

    assert current_version(connection) == 1
    assert connection.execute("SELECT id FROM gadget").fetchall() == [(1,)]
    tables = {
        row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "part" not in tables
    connection.close()


def test_reopening_an_existing_database_does_not_reapply_steps(tmp_path: Path) -> None:
    path = tmp_path / "reopen.sqlite3"
    connection = db.connect(path)
    migrate(connection)
    connection.execute(
        "INSERT INTO watchlist (ecosystem, package_name, added_at, note) "
        "VALUES ('npm', 'kept-pkg', '2026-11-05T12:00:00+00:00', NULL)"
    )
    connection.commit()
    connection.close()

    reopened = db.connect(path)
    migrate(reopened)
    names = [row[0] for row in reopened.execute("SELECT package_name FROM watchlist")]
    assert names == ["kept-pkg"]
    reopened.close()


def test_wal_and_foreign_keys_are_enabled(conn: sqlite3.Connection) -> None:
    migrate(conn)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert int(conn.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
