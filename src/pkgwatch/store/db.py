"""SQLite connection and the forward-only migration runner.

Every statement here is either a PRAGMA or DDL issued inside an explicit transaction, and
a failed step rolls back as a whole: an old database is either migrated or untouched, never
half-built. Migrations only ever move forward, so a database written by a newer pkgwatch is
refused rather than rewritten backwards.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pkgwatch.models import SCHEMA_VERSION

TARGET_VERSION = 1


@dataclass(frozen=True)
class Migration:
    """One forward step: integer version, why it exists, and the DDL that implements it."""

    version: int
    description: str
    statements: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.version < 1:
            raise ValueError("migration versions start at 1")
        if not self.statements:
            raise ValueError(f"migration {self.version} has no statements")


class SchemaTooNew(Exception):
    """The database is ahead of this build; refusing to downgrade it."""


class MigrationFailed(Exception):
    """A step raised and was rolled back. The database is still at its previous version."""


def connect(path: Path) -> sqlite3.Connection:
    """Open a WAL connection with foreign keys on and transactions managed by hand."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = NORMAL")
    return connection


def current_version(connection: sqlite3.Connection) -> int:
    row = connection.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row is not None else 0


def schema_version(connection: sqlite3.Connection) -> int:
    """Record-schema version this connection can hold (SPEC 6.2), guarded by migration state."""
    if current_version(connection) != TARGET_VERSION:
        raise MigrationFailed(
            f"database is at user_version {current_version(connection)}, "
            f"expected {TARGET_VERSION}; call migrate() first"
        )
    return SCHEMA_VERSION


def migrate(
    connection: sqlite3.Connection,
    migrations: Sequence[Migration] | None = None,
) -> int:
    """Apply every step above the database's current version. Returns the version reached."""
    steps = _declared_migrations() if migrations is None else tuple(migrations)
    if sorted(step.version for step in steps) != [step.version for step in steps]:
        raise ValueError("migrations must be ordered by version")

    reached = current_version(connection)
    if steps:
        target = steps[-1].version
        if reached > target:
            raise SchemaTooNew(
                f"database is at user_version {reached}; this build migrates to {target}"
            )

    for step in steps:
        if step.version <= reached:
            continue
        connection.execute("BEGIN")
        try:
            for statement in step.statements:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {int(step.version)}")
        except sqlite3.Error as exc:
            connection.execute("ROLLBACK")
            raise MigrationFailed(f"step {step.version} ({step.description}): {exc}") from exc
        connection.execute("COMMIT")
        reached = step.version

    return reached


def _declared_migrations() -> tuple[Migration, ...]:
    """Late import: ``schema`` builds its steps from ``Migration`` defined here."""
    from pkgwatch.store.schema import MIGRATIONS

    return MIGRATIONS
