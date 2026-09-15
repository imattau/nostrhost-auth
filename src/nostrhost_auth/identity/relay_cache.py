"""Cache for fetched NIP-65 relay lists, keyed by pubkey.

Separate SQLite file from mappings.py's identities.db - this data has a
completely different lifecycle (fetched from the network, expires, is
purely advisory) and no foreign-key relationship to the identity table
worth coupling the two schemas over.
"""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from nostrhost_auth._sqlite import connect, connect_and_init
from nostrhost_auth.identity.relays import RelayEntry

SCHEMA = """
CREATE TABLE IF NOT EXISTS relay_lists (
    pubkey     TEXT PRIMARY KEY,
    relays     TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class CachedRelayList:
    relays: list[RelayEntry]
    fetched_at: int

    def age_seconds(self) -> int:
        return max(0, int(time.time()) - self.fetched_at)


def _encode(relays: list[RelayEntry]) -> str:
    # Relay URLs come from an untrusted network source (an event's own
    # tags), so this is JSON-encoded rather than delimiter-joined -
    # nothing in a URL string can break out of a JSON array element.
    return json.dumps([{"url": r.url, "read": r.read, "write": r.write} for r in relays])


def _decode(raw: str) -> list[RelayEntry]:
    return [RelayEntry(url=item["url"], read=item["read"], write=item["write"]) for item in json.loads(raw)]


class RelayCache:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        connect_and_init(self._db_path, SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return connect(self._db_path)

    def get(self, pubkey_hex: str) -> CachedRelayList | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT relays, fetched_at FROM relay_lists WHERE pubkey = ?", (pubkey_hex,)
            ).fetchone()
        if row is None:
            return None
        return CachedRelayList(relays=_decode(row["relays"]), fetched_at=row["fetched_at"])

    def store(self, pubkey_hex: str, relays: list[RelayEntry]) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO relay_lists (pubkey, relays, fetched_at)
                VALUES (?, ?, ?)
                ON CONFLICT(pubkey) DO UPDATE SET
                    relays = excluded.relays,
                    fetched_at = excluded.fetched_at
                """,
                (pubkey_hex, _encode(relays), int(time.time())),
            )
            conn.commit()
