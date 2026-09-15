"""Shared SQLite connect/init boilerplate for this package's stores.

``auth/challenge.py``, ``identity/mappings.py``, ``identity/relay_cache.py``
and ``identity/signer_sessions.py`` each own a single SQLite file and follow
the same shape: make sure the parent directory exists, open a connection
with ``row_factory = sqlite3.Row``, and apply a schema once on first open.
That boilerplate lives here instead of being copy-pasted four times.

WAL journal mode plus a busy timeout matter whenever more than one
connection can touch the same file - multiple ``uvicorn`` workers, or a CLI
invocation running alongside the service. ``ChallengeStore`` was the only
one of the four that applied this; the other three now get it too via
:func:`connect`, which is a deliberate behavior change (see the PR
description), not just a refactor.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

DEFAULT_BUSY_TIMEOUT_MS = 5000


def connect(
    db_path: Path,
    *,
    wal: bool = True,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
) -> sqlite3.Connection:
    """Open one connection to ``db_path`` with this package's standard settings."""
    conn = sqlite3.connect(db_path, timeout=busy_timeout_ms / 1000)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
    if wal:
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def connect_and_init(
    db_path: Path,
    schema: str,
    *,
    wal: bool = True,
    busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    init: Callable[[sqlite3.Connection], None] | None = None,
) -> None:
    """Ensure ``db_path``'s parent directory exists and its schema is applied.

    Called once from a store's ``__init__``, before any other connection to
    the same file is opened. ``schema`` is run via ``executescript``. When
    given, ``init`` runs afterwards on the same connection, before commit -
    used by :class:`~nostrhost_auth.identity.mappings.MappingStore` for its
    one-time legacy-table migration.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(db_path, wal=wal, busy_timeout_ms=busy_timeout_ms)) as conn:
        conn.executescript(schema)
        if init is not None:
            init(conn)
        conn.commit()


def soft_revoke_row(
    conn: sqlite3.Connection,
    table: str,
    *,
    id_column: str,
    id_value: object,
    ynh_username: str,
    set_sql: str,
    active_sql: str,
) -> bool:
    """Run the "soft revoke" UPDATE shared by every "revoke this row, once,
    only if it's mine" mutation in this package (an identity's `enabled`
    flag, a signer session's `revoked_at`).

    Sets `set_sql` (its only bound parameter is the revocation timestamp)
    on the single row in `table` identified by `id_column = id_value` and
    owned by `ynh_username`, but only while `active_sql` (a literal SQL
    condition, no parameters of its own) still holds. Does not commit -
    callers share this connection with their own transaction. `table`,
    `id_column`, `set_sql` and `active_sql` are fixed strings supplied by
    this module's own methods, never caller/request data.
    """
    now = int(time.time())
    cursor = conn.execute(
        f"UPDATE {table} SET {set_sql} WHERE {id_column} = ? AND ynh_username = ? AND {active_sql}",
        (now, id_value, ynh_username),
    )
    return cursor.rowcount == 1
