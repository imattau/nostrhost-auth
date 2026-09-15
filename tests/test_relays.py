from __future__ import annotations

import asyncio

import pytest
from nostr_sdk import EventBuilder, Keys, Kind, LocalRelayBuilder, Tag

from nostrhost_auth.identity.relays import (
    RELAY_LIST_KIND,
    RelayEntry,
    fetch_relay_list,
    newest_relay_list_event,
    parse_relay_list,
    verified_relay_list_event,
)


def _relay_list_event(keys: Keys, tags: list[list[str]], *, created_at: int | None = None):
    builder = EventBuilder(Kind(RELAY_LIST_KIND), "").tags([Tag.parse(t) for t in tags])
    if created_at is not None:
        builder = builder.custom_created_at(__import__("nostr_sdk").Timestamp.from_secs(created_at))
    unsigned = builder.finalize_unsigned(keys.public_key())
    return keys.sign_event(unsigned)


def test_parse_relay_list_defaults_to_both_directions():
    keys = Keys.generate()
    event = _relay_list_event(keys, [["r", "wss://relay.example"]])
    assert parse_relay_list(event) == [RelayEntry(url="wss://relay.example", read=True, write=True)]


def test_parse_relay_list_respects_read_write_markers():
    keys = Keys.generate()
    event = _relay_list_event(
        keys,
        [["r", "wss://read-only.example", "read"], ["r", "wss://write-only.example", "write"]],
    )
    assert parse_relay_list(event) == [
        RelayEntry(url="wss://read-only.example", read=True, write=False),
        RelayEntry(url="wss://write-only.example", read=False, write=True),
    ]


def test_parse_relay_list_ignores_non_r_tags():
    keys = Keys.generate()
    event = _relay_list_event(keys, [["r", "wss://relay.example"], ["p", "deadbeef"]])
    assert parse_relay_list(event) == [RelayEntry(url="wss://relay.example", read=True, write=True)]


def test_newest_relay_list_event_picks_the_latest():
    keys = Keys.generate()
    older = _relay_list_event(keys, [["r", "wss://old.example"]], created_at=1000)
    newer = _relay_list_event(keys, [["r", "wss://new.example"]], created_at=2000)
    assert newest_relay_list_event([older, newer]) is newer
    assert newest_relay_list_event([newer, older]) is newer


def test_newest_relay_list_event_empty_list_is_none():
    assert newest_relay_list_event([]) is None


def test_verified_relay_list_event_rejects_forged_author():
    """A malicious bootstrap relay can return a kind-10002 for any author;
    only events actually signed by the requested pubkey may be used."""
    victim = Keys.generate()
    attacker = Keys.generate()
    forged = _relay_list_event(attacker, [["r", "wss://evil.example"]])
    assert verified_relay_list_event([forged], victim.public_key().to_hex()) is None


def test_verified_relay_list_event_rejects_tampered_signature():
    keys = Keys.generate()
    event = _relay_list_event(keys, [["r", "wss://relay.example"]])
    # Swap the content after signing: the id/signature no longer verify.
    tampered = event.__class__.from_json(
        event.as_json().replace("wss://relay.example", "wss://evil.example")
    )
    assert verified_relay_list_event([tampered], keys.public_key().to_hex()) is None


def test_verified_relay_list_event_accepts_authentic():
    keys = Keys.generate()
    event = _relay_list_event(keys, [["r", "wss://relay.example"]])
    assert verified_relay_list_event([event], keys.public_key().to_hex()) is event


def test_parse_relay_list_skips_unsafe_urls():
    keys = Keys.generate()
    event = _relay_list_event(
        keys,
        [
            ["r", "wss://relay.example"],
            ["r", "http://plaintext.example"],
            ["r", "ws://user:pass@relay.example"],
            ["r", "ws://127.0.0.1:4848"],
            ["r", "wss://10.0.0.5"],
            ["r", "not a url"],
        ],
    )
    assert parse_relay_list(event) == [RelayEntry(url="wss://relay.example", read=True, write=True)]


@pytest.mark.asyncio
async def test_fetch_relay_list_end_to_end_against_a_local_relay():
    """Real round trip: publish a signed kind-10002 event to an in-process
    relay, then fetch it back through the exact same code path
    ynh/relay_lookup_server.py drives - nothing here is mocked."""
    from nostr_sdk import Client

    relay = LocalRelayBuilder().build()
    run_task = asyncio.create_task(relay.run())
    try:
        await asyncio.sleep(0.2)
        url = await relay.url()

        keys = Keys.generate()
        event = _relay_list_event(keys, [["r", "wss://relay.example"], ["r", "wss://write.example", "write"]])

        publisher = Client()
        try:
            await publisher.add_relay(url)
            await publisher.connect()
            await asyncio.sleep(0.3)
            await publisher.send_event(event)
        finally:
            await publisher.shutdown()

        result = await fetch_relay_list(keys.public_key().to_hex(), bootstrap_relays=[url], timeout_seconds=5)
        assert sorted(result, key=lambda r: r.url) == [
            RelayEntry(url="wss://relay.example", read=True, write=True),
            RelayEntry(url="wss://write.example", read=False, write=True),
        ]
    finally:
        run_task.cancel()


@pytest.mark.asyncio
async def test_fetch_relay_list_returns_empty_for_a_pubkey_with_no_declaration():
    relay = LocalRelayBuilder().build()
    run_task = asyncio.create_task(relay.run())
    try:
        await asyncio.sleep(0.2)
        url = await relay.url()
        keys = Keys.generate()
        result = await fetch_relay_list(keys.public_key().to_hex(), bootstrap_relays=[url], timeout_seconds=2)
        assert result == []
    finally:
        run_task.cancel()


@pytest.mark.asyncio
async def test_fetch_relay_list_with_no_bootstrap_relays_returns_empty():
    keys = Keys.generate()
    assert await fetch_relay_list(keys.public_key().to_hex(), bootstrap_relays=[], timeout_seconds=1) == []
