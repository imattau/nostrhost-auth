import json

import pytest
from nostr_sdk import EventBuilder, Keys, Kind, Tag

from nostrhost_auth.auth.nostr_verify import (
    CHALLENGE_EVENT_KIND,
    InvalidEvent,
    verify_challenge_response,
)

DOMAIN = "example.org"
ACTION = "yunohost-login"
NONCE = "test-nonce-123"


def _signed_challenge_event(keys: Keys, *, nonce=NONCE, domain=DOMAIN, action=ACTION, kind=CHALLENGE_EVENT_KIND) -> str:
    builder = EventBuilder(Kind(kind), "").tags(
        [
            Tag.parse(["challenge", nonce]),
            Tag.parse(["domain", domain]),
            Tag.parse(["action", action]),
        ]
    )
    return builder.finalize(keys).as_json()


def test_valid_response_returns_signer_pubkey():
    keys = Keys.generate()
    event_json = _signed_challenge_event(keys)

    pubkey = verify_challenge_response(
        event_json,
        expected_nonce=NONCE,
        expected_domain=DOMAIN,
        expected_action=ACTION,
        issued_at=0,
        expires_at=10_000_000_000,
    )

    assert pubkey == keys.public_key().to_hex()


def test_tampered_content_is_rejected():
    keys = Keys.generate()
    event_json = _signed_challenge_event(keys)
    raw = json.loads(event_json)
    raw["content"] = "tampered"

    with pytest.raises(InvalidEvent):
        verify_challenge_response(
            json.dumps(raw),
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=10_000_000_000,
        )


def test_wrong_nonce_is_rejected():
    keys = Keys.generate()
    event_json = _signed_challenge_event(keys, nonce="different-nonce")

    with pytest.raises(InvalidEvent, match="challenge"):
        verify_challenge_response(
            event_json,
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=10_000_000_000,
        )


def test_wrong_domain_is_rejected():
    keys = Keys.generate()
    event_json = _signed_challenge_event(keys, domain="evil.example")

    with pytest.raises(InvalidEvent, match="domain"):
        verify_challenge_response(
            event_json,
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=10_000_000_000,
        )


def test_wrong_action_is_rejected():
    keys = Keys.generate()
    event_json = _signed_challenge_event(keys, action="yunohost-link")

    with pytest.raises(InvalidEvent, match="action"):
        verify_challenge_response(
            event_json,
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=10_000_000_000,
        )


def test_wrong_kind_is_rejected():
    keys = Keys.generate()
    event_json = _signed_challenge_event(keys, kind=1)

    with pytest.raises(InvalidEvent, match="kind"):
        verify_challenge_response(
            event_json,
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=10_000_000_000,
        )


def test_created_at_outside_window_is_rejected():
    keys = Keys.generate()
    event_json = _signed_challenge_event(keys)

    with pytest.raises(InvalidEvent, match="created_at"):
        verify_challenge_response(
            event_json,
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=1,
            clock_skew=0,
        )


def test_malformed_json_is_rejected():
    with pytest.raises(InvalidEvent):
        verify_challenge_response(
            "not json",
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=10_000_000_000,
        )


def test_forged_signature_is_rejected():
    keys = Keys.generate()
    other_keys = Keys.generate()
    event_json = _signed_challenge_event(keys)
    raw = json.loads(event_json)
    # Swap in another key's pubkey but keep the original signature.
    raw["pubkey"] = other_keys.public_key().to_hex()

    with pytest.raises(InvalidEvent):
        verify_challenge_response(
            json.dumps(raw),
            expected_nonce=NONCE,
            expected_domain=DOMAIN,
            expected_action=ACTION,
            issued_at=0,
            expires_at=10_000_000_000,
        )
