"""Single-use, domain- and action-bound login/link challenges (PLAN.md Phase 3).

A challenge binds at minimum: nonce, domain, requested action, issued time,
expiry. It must be consumed atomically on successful authentication so it
cannot be replayed - against this server or another YunoHost instance.
"""

from __future__ import annotations

from contextlib import closing
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from time import time

DEFAULT_TTL_SECONDS = 90  # PLAN.md Phase 13: 30-120 second expiry


@dataclass(frozen=True)
class Challenge:
    nonce: str
    domain: str
    action: str
    issued_at: int
    expires_at: int


def new_challenge(domain: str, action: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> Challenge:
    now = int(time())
    return Challenge(
        nonce=secrets.token_urlsafe(32),
        domain=domain,
        action=action,
        issued_at=now,
        expires_at=now + ttl_seconds,
    )


class ChallengeStore:
    """Tracks outstanding challenges and consumes them exactly once.

    With a database path, challenges survive a service restart and multiple
    service instances can safely share the store.  The in-memory mode is
    retained for small callers and unit tests that do not need persistence.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS challenges (
        nonce       TEXT PRIMARY KEY,
        domain      TEXT NOT NULL,
        action      TEXT NOT NULL,
        issued_at   INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL,
        consumed_at INTEGER
    );
    CREATE INDEX IF NOT EXISTS challenges_expiry_idx
        ON challenges (expires_at);
    """

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        *,
        db_path: Path | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._ttl_seconds = ttl_seconds
        self._db_path = db_path
        self._pending: dict[str, Challenge] = {}

        if self._db_path is not None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as conn:
                conn.executescript(self.SCHEMA)
                conn.commit()

    def _connect(self) -> sqlite3.Connection:
        if self._db_path is None:
            raise RuntimeError("database connection requested for an in-memory challenge store")
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def issue(self, domain: str, action: str) -> Challenge:
        challenge = new_challenge(domain, action, self._ttl_seconds)
        if self._db_path is None:
            self._pending[challenge.nonce] = challenge
            return challenge

        now = int(time())
        with closing(self._connect()) as conn:
            # Used challenges remain until their natural expiry, preserving
            # replay rejection without allowing the database to grow forever.
            conn.execute("DELETE FROM challenges WHERE expires_at < ?", (now,))
            conn.execute(
                """
                INSERT INTO challenges
                    (nonce, domain, action, issued_at, expires_at, consumed_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (
                    challenge.nonce,
                    challenge.domain,
                    challenge.action,
                    challenge.issued_at,
                    challenge.expires_at,
                ),
            )
            conn.commit()
        return challenge

    def consume(self, nonce: str) -> Challenge | None:
        now = int(time())
        if self._db_path is None:
            challenge = self._pending.pop(nonce, None)
            if challenge is None:
                return None
            if challenge.expires_at < now:
                return None
            return challenge

        with closing(self._connect()) as conn:
            # BEGIN IMMEDIATE serializes the read-and-mark pair.  This is
            # important when uvicorn is later run with multiple workers or
            # another local helper shares the database.
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT nonce, domain, action, issued_at, expires_at
                FROM challenges
                WHERE nonce = ? AND consumed_at IS NULL
                """,
                (nonce,),
            ).fetchone()

            if row is None:
                conn.commit()
                return None

            conn.execute(
                "UPDATE challenges SET consumed_at = ? WHERE nonce = ? AND consumed_at IS NULL",
                (now, nonce),
            )
            conn.commit()

        if row["expires_at"] < now:
            return None
        return Challenge(
            nonce=row["nonce"],
            domain=row["domain"],
            action=row["action"],
            issued_at=row["issued_at"],
            expires_at=row["expires_at"],
        )
