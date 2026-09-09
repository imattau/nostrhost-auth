from __future__ import annotations

import time

from nostrhost_auth.identity.relay_cache import RelayCache
from nostrhost_auth.identity.relays import RelayEntry

PUBKEY = "a" * 64


def test_get_on_empty_cache_returns_none(tmp_path):
    cache = RelayCache(tmp_path / "relays.db")
    assert cache.get(PUBKEY) is None


def test_store_then_get_round_trips(tmp_path):
    cache = RelayCache(tmp_path / "relays.db")
    entries = [RelayEntry(url="wss://relay.example", read=True, write=False)]
    cache.store(PUBKEY, entries)

    cached = cache.get(PUBKEY)
    assert cached is not None
    assert cached.relays == entries
    assert cached.age_seconds() < 5


def test_store_overwrites_the_previous_entry(tmp_path):
    cache = RelayCache(tmp_path / "relays.db")
    cache.store(PUBKEY, [RelayEntry(url="wss://old.example", read=True, write=True)])
    cache.store(PUBKEY, [RelayEntry(url="wss://new.example", read=True, write=True)])

    cached = cache.get(PUBKEY)
    assert cached.relays == [RelayEntry(url="wss://new.example", read=True, write=True)]


def test_age_seconds_reflects_fetched_at(tmp_path):
    cache = RelayCache(tmp_path / "relays.db")
    cache.store(PUBKEY, [])
    cached = cache.get(PUBKEY)
    assert cached.fetched_at <= int(time.time())


def test_relay_url_with_special_characters_round_trips_safely(tmp_path):
    """Relay URLs come from an untrusted event's own tags - guard against
    a delimiter-based encoding letting one break out of its own record."""
    cache = RelayCache(tmp_path / "relays.db")
    tricky = RelayEntry(url='wss://evil.example/\t\n"}]{[', read=True, write=True)
    cache.store(PUBKEY, [tricky])
    assert cache.get(PUBKEY).relays == [tricky]
