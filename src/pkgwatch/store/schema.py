"""Schema for the three M2 tables, as forward-only migration steps.

The DDL lives in Python rather than ``schema.sql`` so a wheel build cannot ship a binary
without its schema file. M3 appends a ``Migration`` here and bumps ``db.TARGET_VERSION``;
it never edits step 1, because an already-distributed database has it applied.
"""

from __future__ import annotations

from pkgwatch.store.db import Migration

RELEASES = """
CREATE TABLE releases (
    ecosystem             TEXT    NOT NULL,
    package_name          TEXT    NOT NULL,
    version               TEXT    NOT NULL,
    published_at          TEXT    NOT NULL,
    previous_version      TEXT,
    previous_published_at TEXT,
    tarball_url           TEXT    NOT NULL,
    sha256                TEXT    NOT NULL,
    size                  INTEGER NOT NULL,
    registry_snapshot     TEXT    NOT NULL DEFAULT '{}',
    source_endpoint       TEXT    NOT NULL,
    retracted             INTEGER NOT NULL DEFAULT 0,
    status                TEXT    NOT NULL DEFAULT 'pending',
    stage_error           TEXT,
    analysis_incomplete   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ecosystem, package_name, version)
)
"""

RELEASES_BY_PACKAGE = """
CREATE INDEX releases_by_package
    ON releases (ecosystem, package_name, published_at DESC, version DESC)
"""

WATCHLIST = """
CREATE TABLE watchlist (
    ecosystem    TEXT NOT NULL,
    package_name TEXT NOT NULL,
    added_at     TEXT NOT NULL,
    note         TEXT,
    PRIMARY KEY (ecosystem, package_name)
)
"""

RUNS = """
CREATE TABLE runs (
    run_id              TEXT    NOT NULL PRIMARY KEY,
    started_at          TEXT    NOT NULL,
    finished_at         TEXT,
    manifest_path       TEXT    NOT NULL,
    manifest            TEXT    NOT NULL,
    rule_set_version    TEXT    NOT NULL,
    weights_version     TEXT    NOT NULL,
    schema_version      INTEGER NOT NULL,
    sqlite_user_version INTEGER NOT NULL
)
"""

RUNS_BY_START = """
CREATE INDEX runs_by_start ON runs (started_at DESC, run_id DESC)
"""

MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        description="release status, watchlist, run manifests",
        statements=(RELEASES, RELEASES_BY_PACKAGE, WATCHLIST, RUNS, RUNS_BY_START),
    ),
)
