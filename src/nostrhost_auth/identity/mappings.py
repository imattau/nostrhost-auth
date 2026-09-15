"""ynh_username <-> Nostr pubkey mapping store (PLAN.md Phase 4).

SQLite-backed. Pubkeys are stored as canonical hex, never as npub - npub is
decoded/encoded only at the UI boundary (see identity/npub.py). Multiple
identities may belong to one user; each pubkey may belong to at most one user.
The old one-row-per-user ``users`` table is migrated into the new table on
first open without deleting it, so an interrupted upgrade remains recoverable.
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from nostrhost_auth._sqlite import connect, connect_and_init, soft_revoke_row


@dataclass(frozen=True)
class Identity:
    ynh_username: str
    pubkey: str
    created_at: int
    last_used: int | None
    enabled: bool
    identity_id: int | None = None
    signer_type: str = "unknown"
    label: str | None = None
    linked_by: str = "self-service"
    revoked_at: int | None = None


class PubkeyAlreadyLinked(ValueError):
    """Raised when linking a pubkey that's already linked to a different user."""


class MappingStore:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS identities (
        identity_id INTEGER PRIMARY KEY AUTOINCREMENT,
        ynh_username TEXT NOT NULL,
        pubkey       TEXT NOT NULL UNIQUE,
        created_at   INTEGER NOT NULL,
        last_used    INTEGER,
        enabled      INTEGER NOT NULL DEFAULT 1,
        signer_type  TEXT NOT NULL DEFAULT 'unknown',
        label        TEXT,
        linked_by    TEXT NOT NULL DEFAULT 'self-service',
        revoked_at   INTEGER
    );
    CREATE INDEX IF NOT EXISTS identities_username_idx
        ON identities (ynh_username, created_at);
    """

    LEGACY_MIGRATION_VERSION = 1

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        connect_and_init(self._db_path, self.SCHEMA, init=self._migrate_legacy_users)

    def _connect(self) -> sqlite3.Connection:
        conn = connect(self._db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @classmethod
    def _migrate_legacy_users(cls, conn: sqlite3.Connection) -> None:
        """Copy the original one-identity-per-user table once.

        The legacy table is intentionally left in place.  Keeping it makes
        the migration non-destructive and gives an administrator a recovery
        artifact if an upgrade is interrupted.
        """
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version >= cls.LEGACY_MIGRATION_VERSION:
            return

        legacy_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()
        if legacy_exists:
            conn.execute(
                """
                INSERT OR IGNORE INTO identities
                    (ynh_username, pubkey, created_at, last_used, enabled)
                SELECT ynh_username, pubkey, created_at, last_used, enabled
                FROM users
                """
            )

        conn.execute(f"PRAGMA user_version = {cls.LEGACY_MIGRATION_VERSION}")

    def link(
        self,
        ynh_username: str,
        pubkey_hex: str,
        *,
        signer_type: str = "unknown",
        label: str | None = None,
        linked_by: str = "self-service",
    ) -> None:
        """Link `pubkey_hex`, replacing all identities for that user.

        This retains the original Phase 5 replacement semantics.  New
        multi-identity callers should use :meth:`add_identity` instead.
        """
        with closing(self._connect()) as conn:
            existing = conn.execute(
                "SELECT ynh_username FROM identities WHERE pubkey = ?", (pubkey_hex,)
            ).fetchone()
            if existing is not None and existing["ynh_username"] != ynh_username:
                raise PubkeyAlreadyLinked(
                    f"pubkey already linked to a different account ({existing['ynh_username']!r})"
                )

            conn.execute("DELETE FROM identities WHERE ynh_username = ?", (ynh_username,))
            conn.execute(
                """
                INSERT INTO identities
                    (ynh_username, pubkey, created_at, enabled, signer_type, label, linked_by)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                """,
                (ynh_username, pubkey_hex, int(time.time()), signer_type, label, linked_by),
            )
            conn.commit()

    def add_identity(
        self,
        ynh_username: str,
        pubkey_hex: str,
        *,
        signer_type: str = "unknown",
        label: str | None = None,
        linked_by: str = "self-service",
    ) -> Identity:
        """Add an identity without removing the user's other identities."""
        created_at = int(time.time())
        with closing(self._connect()) as conn:
            existing = conn.execute(
                "SELECT ynh_username FROM identities WHERE pubkey = ?", (pubkey_hex,)
            ).fetchone()
            if existing is not None and existing["ynh_username"] != ynh_username:
                raise PubkeyAlreadyLinked(
                    f"pubkey already linked to a different account ({existing['ynh_username']!r})"
                )
            if existing is not None:
                raise PubkeyAlreadyLinked("pubkey is already linked to this account")

            cursor = conn.execute(
                """
                INSERT INTO identities
                    (ynh_username, pubkey, created_at, enabled, signer_type, label, linked_by)
                VALUES (?, ?, ?, 1, ?, ?, ?)
                """,
                (ynh_username, pubkey_hex, created_at, signer_type, label, linked_by),
            )
            conn.commit()
            identity_id = cursor.lastrowid

        identity = self.get_by_id(identity_id)
        if identity is None:  # pragma: no cover - defensive database invariant
            raise RuntimeError("newly-added identity could not be read back")
        return identity

    def unlink(self, ynh_username: str) -> int:
        """Remove every identity belonging to ``ynh_username``.

        Return the number of rows removed so lifecycle callers (notably the
        YunoHost ``post_user_delete`` hook) can record an auditable cleanup
        result without first racing a separate count query.
        """
        with closing(self._connect()) as conn:
            cursor = conn.execute("DELETE FROM identities WHERE ynh_username = ?", (ynh_username,))
            conn.commit()
            return cursor.rowcount

    def revoke_identity(self, identity_id: int, ynh_username: str) -> bool:
        """Disable one identity, but only when it belongs to `ynh_username`."""
        with closing(self._connect()) as conn:
            revoked = soft_revoke_row(
                conn,
                "identities",
                id_column="identity_id",
                id_value=identity_id,
                ynh_username=ynh_username,
                set_sql="enabled = 0, revoked_at = ?",
                active_sql="enabled = 1",
            )
            conn.commit()
            return revoked

    def set_identity_enabled(self, identity_id: int, ynh_username: str, enabled: bool) -> bool:
        """Enable or re-enable one identity (used by the identity projector
        to materialise an identity-definition event's `enabled` state). Only
        touches identities belonging to `ynh_username`."""
        if enabled:
            with closing(self._connect()) as conn:
                cursor = conn.execute(
                    """
                    UPDATE identities
                    SET enabled = 1, revoked_at = NULL
                    WHERE identity_id = ? AND ynh_username = ?
                    """,
                    (identity_id, ynh_username),
                )
                conn.commit()
                return cursor.rowcount == 1
        return self.revoke_identity(identity_id, ynh_username)

    def get_identity_by_pubkey(self, pubkey_hex: str) -> Identity | None:
        """Like :meth:`get_by_pubkey` but ignores the enabled flag — lets the
        identity projector re-enable a revoked identity rather than creating
        a duplicate row."""
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM identities WHERE pubkey = ?", (pubkey_hex,)
            ).fetchone()
            return self._row_to_identity(row) if row else None

    def update_identity_label(
        self, identity_id: int, ynh_username: str, label: str | None
    ) -> Identity | None:
        """Update one active identity's display label for its owning user."""
        return self._update_active_identity(identity_id, ynh_username, label=label)

    def update_identity_profile(
        self,
        identity_id: int,
        ynh_username: str,
        *,
        signer_type: str,
        label: str | None,
    ) -> Identity | None:
        """Update an active identity's signer_type and display label together.

        Used by the identity projector when a re-published identity-definition
        event (same ``d`` tag / pubkey, still enabled) carries a new
        signer_type or label — the row is already materialised, so the event
        updates the profile in place rather than creating a duplicate.
        """
        return self._update_active_identity(
            identity_id, ynh_username, signer_type=signer_type, label=label
        )

    def _update_active_identity(self, identity_id: int, ynh_username: str, **fields: object) -> Identity | None:
        """Shared shape behind :meth:`update_identity_label` and
        :meth:`update_identity_profile`: update `fields` on the one active
        identity matching `identity_id`/`ynh_username`, then refetch it.
        Returns None (without refetching) if no such row exists - most
        commonly because it belongs to a different user or is disabled.
        """
        assignments = ", ".join(f"{column} = ?" for column in fields)
        with closing(self._connect()) as conn:
            cursor = conn.execute(
                f"""
                UPDATE identities
                SET {assignments}
                WHERE identity_id = ? AND ynh_username = ? AND enabled = 1
                """,
                (*fields.values(), identity_id, ynh_username),
            )
            conn.commit()
            if cursor.rowcount != 1:
                return None
        return self.get_by_id(identity_id)

    def get_by_id(self, identity_id: int) -> Identity | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM identities WHERE identity_id = ?", (identity_id,)
            ).fetchone()
            return self._row_to_identity(row) if row else None

    def get_by_pubkey(self, pubkey_hex: str) -> Identity | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM identities WHERE pubkey = ? AND enabled = 1", (pubkey_hex,)
            ).fetchone()
            return self._row_to_identity(row) if row else None

    def get_by_username(self, ynh_username: str) -> Identity | None:
        """Return one identity for compatibility with the original API.

        New callers that need the complete account view should use
        :meth:`list_by_username`.
        """
        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT * FROM identities
                WHERE ynh_username = ?
                ORDER BY enabled DESC, created_at DESC, identity_id DESC
                LIMIT 1
                """,
                (ynh_username,),
            ).fetchone()
            return self._row_to_identity(row) if row else None

    def list_by_username(self, ynh_username: str, *, include_disabled: bool = True) -> list[Identity]:
        """Return all identities for an account, newest first."""
        query = "SELECT * FROM identities WHERE ynh_username = ?"
        params: tuple[object, ...] = (ynh_username,)
        if not include_disabled:
            query += " AND enabled = 1"
        query += " ORDER BY created_at DESC, identity_id DESC"
        with closing(self._connect()) as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_identity(row) for row in rows]

    def touch_last_used(self, ynh_username: str) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE identities SET last_used = ? WHERE ynh_username = ? AND enabled = 1",
                (int(time.time()), ynh_username),
            )
            conn.commit()

    def touch_identity(self, identity_id: int) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE identities SET last_used = ? WHERE identity_id = ? AND enabled = 1",
                (int(time.time()), identity_id),
            )
            conn.commit()

    def list_all(self) -> list[Identity]:
        """For the admin CLI and future account-management UI."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM identities ORDER BY ynh_username, created_at DESC, identity_id DESC"
            ).fetchall()
            return [self._row_to_identity(row) for row in rows]

    @staticmethod
    def _row_to_identity(row: sqlite3.Row) -> Identity:
        return Identity(
            ynh_username=row["ynh_username"],
            pubkey=row["pubkey"],
            created_at=row["created_at"],
            last_used=row["last_used"],
            enabled=bool(row["enabled"]),
            identity_id=row["identity_id"],
            signer_type=row["signer_type"],
            label=row["label"],
            linked_by=row["linked_by"],
            revoked_at=row["revoked_at"],
        )
