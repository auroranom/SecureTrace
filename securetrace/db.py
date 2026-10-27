from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS requirements (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'IDENTIFIED',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS requirement_files (
    requirement_id TEXT NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    PRIMARY KEY (requirement_id, file_path)
);

CREATE TABLE IF NOT EXISTS checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id TEXT NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
    check_name TEXT NOT NULL,
    result TEXT NOT NULL,
    verification_complete INTEGER NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '',
    commit_hash TEXT,
    ran_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requirement_id TEXT,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_requirement_files_path
    ON requirement_files(file_path);
CREATE INDEX IF NOT EXISTS idx_checks_requirement
    ON checks(requirement_id, ran_at);
"""

# Additive milestone schema. Deliberately excluded from SCHEMA: existing
# repositories must opt in with `securetrace migrate` before using mappings.
MAPPING_SCHEMA = """
CREATE TABLE IF NOT EXISTS requirement_tests (
    requirement_id TEXT NOT NULL REFERENCES requirements(id) ON DELETE CASCADE,
    test_file TEXT NOT NULL,
    test_id TEXT NOT NULL,
    verification_complete INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    PRIMARY KEY (requirement_id, test_file, test_id)
);
CREATE INDEX IF NOT EXISTS idx_requirement_tests_target
    ON requirement_tests(test_file, test_id);
"""


def database_path(root: Path) -> Path:
    return root / ".securetrace" / "securetrace.db"


class LedgerError(sqlite3.DatabaseError):
    """The ledger exists but cannot be used. Subclasses sqlite3.DatabaseError so older handlers still match.

    SecureTrace never deletes, recreates or overwrites an unreadable ledger: the audit
    history may be recoverable, and silently starting a fresh one would hide it.
    """


@contextmanager
def connect(root: Path) -> Iterator[sqlite3.Connection]:
    """Open, initialize, and reliably close a ledger connection."""
    path = database_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        connection = sqlite3.connect(path, timeout=15.0)   # concurrent hook processes queue instead of failing
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(SCHEMA)
    except sqlite3.DatabaseError as exc:
        try:
            connection.close()
        except (NameError, sqlite3.Error):
            pass
        raise LedgerError(
            f"SecureTrace ledger at {path} cannot be opened ({exc}). It has NOT been modified or replaced. "
            "Check permissions and disk space; if it is corrupt, restore it from a backup or move it aside "
            "yourself. Run `python -m securetrace.cli doctor` for diagnostics."
        ) from exc
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def migrate_mappings(root: Path) -> None:
    """Explicitly apply the additive requirement-to-test mapping migration."""
    with connect(root) as connection:
        connection.executescript(MAPPING_SCHEMA)
