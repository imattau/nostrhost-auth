"""NIP-01 event structure and signature verification, plus binding a signed
event to one of our own challenges.

Delegates the actual crypto (event id computation, BIP-340 Schnorr
verification) to `nostr-sdk` (rust-nostr's Python bindings) rather than
hand-rolling NIP-01 serialization and secp256k1 math here - that's exactly
the kind of security-critical parsing this project shouldn't reimplement,
and it's the same library `yunohost-mcp-server` already depends on for the
same job. Never accepts or stores a private key - only public keys and
signed events.
"""

from __future__ import annotations

from nostr_sdk import Event

# Borrowed from NIP-42 ("Authentication of clients to relays"), which
# already establishes the convention of a client signing a throwaway event
# purely to prove control of a pubkey over a server-issued challenge. Our
# domain/action/challenge tags (see verify_challenge_response) pin this
# specifically to us, so it can't be confused with - or replayed as - an
# actual NIP-42 relay-auth event.
CHALLENGE_EVENT_KIND = 22242


class InvalidEvent(ValueError):
    """A signed Nostr event failed to parse, or failed signature/binding checks."""


def parse_and_verify_event(event_json: str) -> Event:
    """Parse a NIP-01 event from JSON and verify its id and signature.

    Raises InvalidEvent for anything from malformed JSON to a bad
    signature - callers only need to catch this one exception type.
    """
    try:
        event = Event.from_json(event_json)
    except Exception as e:
        raise InvalidEvent(f"malformed event: {e}") from e

    if not event.verify():
        raise InvalidEvent("event id/signature does not verify")

    return event


def _tag_value(event: Event, name: str) -> str | None:
    for tag in event.tags():
        values = tag.to_vec()
        if len(values) >= 2 and values[0] == name:
            return values[1]
    return None


def extract_tag_from_raw_event(event: dict, name: str) -> str | None:
    """Like `_tag_value`, but for a not-yet-verified raw NIP-01 event dict
    (straight from the request body's JSON, `tags` as a list of lists).

    Used only to look up *which* pending challenge a client claims to be
    responding to (by its `challenge` tag), before that challenge's own
    domain/action/nonce are checked against the verified event in
    `verify_challenge_response` - never treat the result of this function
    alone as proof of anything, since the event hasn't been signature-
    checked yet at this point.
    """
    tags = event.get("tags")
    if not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, list) and len(tag) >= 2 and tag[0] == name:
            return tag[1]
    return None


def verify_challenge_response(
    event_json: str,
    *,
    expected_nonce: str,
    expected_domain: str,
    expected_action: str,
    issued_at: int,
    expires_at: int,
    clock_skew: int = 60,
) -> str:
    """Verify `event_json` is a validly signed event of kind
    CHALLENGE_EVENT_KIND that attests to exactly this challenge: matching
    `challenge`/`domain`/`action` tags, and a `created_at` within
    [issued_at - clock_skew, expires_at + clock_skew] (PLAN.md Phase 3's
    "timestamp within acceptable bounds" - the single-use nonce is what
    actually prevents replay; this is defense in depth against a
    pre-signed event being held and replayed near the expiry boundary).

    Returns the signer's pubkey (hex) on success. Raises InvalidEvent
    otherwise. Callers are expected to have already looked up and consumed
    the matching challenge by nonce before calling this - this function
    only checks that the event's own claims are internally consistent with
    what was issued, not that the nonce hasn't been used before.
    """
    event = parse_and_verify_event(event_json)

    if event.kind().as_u16() != CHALLENGE_EVENT_KIND:
        raise InvalidEvent(f"unexpected event kind {event.kind().as_u16()!r}")

    if _tag_value(event, "challenge") != expected_nonce:
        raise InvalidEvent("'challenge' tag does not match the issued nonce")
    if _tag_value(event, "domain") != expected_domain:
        raise InvalidEvent("'domain' tag does not match")
    if _tag_value(event, "action") != expected_action:
        raise InvalidEvent("'action' tag does not match")

    created_at = event.created_at().as_secs()
    if not (issued_at - clock_skew <= created_at <= expires_at + clock_skew):
        raise InvalidEvent("event created_at is outside the challenge's validity window")

    return event.author().to_hex()
