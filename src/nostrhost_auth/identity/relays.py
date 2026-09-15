"""NIP-65 (kind 10002) relay-list resolution for a linked pubkey.

Fetches a pubkey's own advertised relay list from a small bootstrap relay
set, via nostr-sdk's relay pool (the same library nostr_verify.py already
delegates crypto to - see that module's docstring for why parsing/crypto
is never hand-rolled here). ynh/relay_lookup_server.py uses this to answer
"what relays does this linked user prefer" for local consumers such as
nostr_catalog, which otherwise only has a single admin-configured relay
list to search.

`add_relay`/`connect` never raise for an unreachable bootstrap relay -
nostr-sdk spawns a background reconnect task instead (see nostr-sdk's own
`Client.connect` docs) - so an all-relays-down bootstrap set looks
identical to "this pubkey has never published a relay list": both return
an empty list once the fetch timeout elapses, not an error. That's the
right behavior for a best-effort augmentation feature.
"""

from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

from nostr_sdk import Client, Event, Filter, Kind, PublicKey, ReqTarget

from nostrhost_auth._nostr_tags import tags_named

RELAY_LIST_KIND = 10002

_ALLOWED_RELAY_SCHEMES = ("ws", "wss")


@dataclass(frozen=True)
class RelayEntry:
    url: str
    read: bool
    write: bool


def _is_safe_relay_url(url: str) -> bool:
    """Whether a network-advertised relay URL is safe to hand to a local
    consumer.

    A user's NIP-65 list is attacker-influenced (any relay in the fetch path
    can return a forged event), so only ws/wss URLs with a host, no embedded
    credentials, and no literal loopback/link-local/private IP are accepted —
    a user-advertised relay must not be able to steer the server into
    connecting to its own internal services (SSRF). Hostnames are not
    resolved here; the signature check above is the primary control.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in _ALLOWED_RELAY_SCHEMES or not parts.hostname:
        return False
    if parts.username or parts.password:
        return False
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        return True
    return not (ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_unspecified)


def parse_relay_list(event: Event) -> list[RelayEntry]:
    """Extract each `r` tag's relay URL and read/write marker (NIP-65).

    A tag's third element is absent (both directions), or "read"/"write"
    to narrow it to one. URLs that fail `_is_safe_relay_url` are dropped.
    """
    entries: list[RelayEntry] = []
    for values in tags_named(event, "r"):
        if not _is_safe_relay_url(values[1]):
            continue
        marker = values[2] if len(values) >= 3 else None
        entries.append(RelayEntry(url=values[1], read=marker in (None, "read"), write=marker in (None, "write")))
    return entries


def newest_relay_list_event(events: list[Event]) -> Event | None:
    """Kind 10002 is replaceable - only the newest declaration from this
    pubkey is authoritative, even though a relay may (incorrectly) hand
    back more than one when queried with a small `limit`."""
    if not events:
        return None
    return max(events, key=lambda event: event.created_at().as_secs())


def verified_relay_list_event(events: list[Event], pubkey_hex: str) -> Event | None:
    """The newest event that is actually authored by `pubkey_hex` and carries
    a valid signature.

    The `authors` filter is advisory: a malicious or compromised bootstrap
    relay can return a forged kind-10002 event for any author, so each event
    is independently author-checked and signature-verified before use. This
    closes relay-list spoofing (which would otherwise let an attacker point a
    victim's preferred-relay resolution at arbitrary endpoints).
    """
    valid: list[Event] = []
    for event in events:
        try:
            if event.author().to_hex() != pubkey_hex:
                continue
            if not event.verify():
                continue
        except Exception:  # noqa: BLE001 - malformed event means failed verification
            continue
        valid.append(event)
    return newest_relay_list_event(valid)


async def fetch_relay_list(
    pubkey_hex: str,
    *,
    bootstrap_relays: list[str],
    timeout_seconds: float,
) -> list[RelayEntry]:
    """Fetch and parse `pubkey_hex`'s own NIP-65 relay list.

    Returns an empty list if the pubkey has never published one, or if no
    bootstrap relay answered within `timeout_seconds` - neither is treated
    as an error; see this module's docstring for why they're
    indistinguishable and why that's fine here.
    """
    if not bootstrap_relays:
        return []

    public_key = PublicKey.parse(pubkey_hex)
    client = Client()
    try:
        for url in bootstrap_relays:
            try:
                await client.add_relay(url)
            except Exception:  # noqa: BLE001 - one bad URL in the list must not block the others
                continue
        await client.connect()

        request = Filter().authors([public_key]).kind(Kind(RELAY_LIST_KIND)).limit(1)
        events = await client.fetch_events(ReqTarget.auto([request]), timeout=datetime.timedelta(seconds=timeout_seconds))
        event = verified_relay_list_event(list(events), pubkey_hex)
        return parse_relay_list(event) if event is not None else []
    finally:
        await client.shutdown()
