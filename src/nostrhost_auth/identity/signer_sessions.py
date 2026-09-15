"""Remote-signer (NIP-46 bunker) session bookkeeping.

Unlike ``identities`` (mappings.py), a signer session isn't an
authority-establishing fact - it doesn't change who can log in as whom, it
just records which bunkers a user has told their browser to remember, so the
account page can show and let them forget them. That means it doesn't need
the operator-signed event-sourcing path identities go through: the portal-api
process (``ynh-portal``) owns this table directly.

The actual NIP-46 client secret key never reaches this store - it lives only
in the browser's localStorage (see public/nostr/nostr-connect-ui.js). What's
persisted here is purely for the user's own visibility: which remote signer
pubkey, over which relays, connected when and used last. Revoking a row here
does not itself terminate the bunker connection (only the browser holding the
client secret key, or the signer app itself, can do that) - it hides the
session from the account page and is best paired with the browser's own
"forget" action.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from nostrhost_auth._sqlite import connect, connect_and_init, soft_revoke_row


@dataclass(frozen=True)
class SignerSession:
    session_id: str
    ynh_username: str
    bunker_pubkey: str
    relays: str  # JSON-encoded list[str]
    label: str | None
    connected_at: int
    last_used: int | None
    revoked_at: int | None


class SignerSessionStore:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS signer_sessions (
        session_id   TEXT PRIMARY KEY,
        ynh_username TEXT NOT NULL,
        bunker_pubkey TEXT NOT NULL,
        relays       TEXT NOT NULL,
        label        TEXT,
        connected_at INTEGER NOT NULL,
        last_used    INTEGER,
        revoked_at   INTEGER
    );
    CREATE INDEX IF NOT EXISTS signer_sessions_username_idx
        ON signer_sessions (ynh_username, connected_at);
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        connect_and_init(self._db_path, self.SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return connect(self._db_path)

    def register(
        self,
        session_id: str,
        ynh_username: str,
        bunker_pubkey: str,
        relays_json: str,
        *,
        label: str | None = None,
    ) -> SignerSession:
        """Record a new session, or refresh an existing one owned by the
        same user (the client reuses the session_id it already saved
        locally when it reconnects to the same bunker)."""
        with closing(self._connect()) as conn:
            existing = conn.execute(
                "SELECT ynh_username FROM signer_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if existing is not None and existing["ynh_username"] != ynh_username:
                raise ValueError("session_id already belongs to a different account")

            now = int(time.time())
            conn.execute(
                """
                INSERT INTO signer_sessions
                    (session_id, ynh_username, bunker_pubkey, relays, label, connected_at, last_used, revoked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(session_id) DO UPDATE SET
                    bunker_pubkey = excluded.bunker_pubkey,
                    relays = excluded.relays,
                    label = excluded.label,
                    last_used = excluded.last_used,
                    revoked_at = NULL
                """,
                (session_id, ynh_username, bunker_pubkey, relays_json, label, now, now),
            )
            conn.commit()

        session = self.get_by_id(session_id)
        assert session is not None  # pragma: no cover - defensive database invariant
        return session

    def revoke(self, session_id: str, ynh_username: str) -> bool:
        with closing(self._connect()) as conn:
            revoked = soft_revoke_row(
                conn,
                "signer_sessions",
                id_column="session_id",
                id_value=session_id,
                ynh_username=ynh_username,
                set_sql="revoked_at = ?",
                active_sql="revoked_at IS NULL",
            )
            conn.commit()
            return revoked

    def touch_last_used(self, session_id: str, ynh_username: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                UPDATE signer_sessions SET last_used = ?
                WHERE session_id = ? AND ynh_username = ? AND revoked_at IS NULL
                """,
                (int(time.time()), session_id, ynh_username),
            )
            conn.commit()

    def get_by_id(self, session_id: str) -> SignerSession | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM signer_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            return self._row_to_session(row) if row else None

    def list_by_username(self, ynh_username: str, *, include_revoked: bool = False) -> list[SignerSession]:
        query = "SELECT * FROM signer_sessions WHERE ynh_username = ?"
        if not include_revoked:
            query += " AND revoked_at IS NULL"
        query += " ORDER BY connected_at DESC"
        with closing(self._connect()) as conn:
            rows = conn.execute(query, (ynh_username,)).fetchall()
            return [self._row_to_session(row) for row in rows]

    def delete_all_for_username(self, ynh_username: str) -> int:
        """Used when a user unlinks every identity - the account has no
        more Nostr identities to attach bunker sessions to."""
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                "DELETE FROM signer_sessions WHERE ynh_username = ?", (ynh_username,)
            )
            conn.commit()
            return cursor.rowcount

    @staticmethod
    def _row_to_session(row: sqlite3.Row) -> SignerSession:
        return SignerSession(
            session_id=row["session_id"],
            ynh_username=row["ynh_username"],
            bunker_pubkey=row["bunker_pubkey"],
            relays=row["relays"],
            label=row["label"],
            connected_at=row["connected_at"],
            last_used=row["last_used"],
            revoked_at=row["revoked_at"],
        )
