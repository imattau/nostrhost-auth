"""npub <-> canonical hex pubkey conversion, for the UI boundary only.

PLAN.md Phase 4: "Do not use npub internally... store the canonical hex
public key." Everything past this module (mappings, linking, verification)
deals exclusively in hex; npub only exists where a human types or reads one.

Delegates to nostr-sdk's own bech32 handling rather than a second
hand-rolled implementation alongside auth/nostr_verify.py's use of it.
"""

from __future__ import annotations

from nostr_sdk import PublicKey


def npub_to_hex(npub: str) -> str:
    # PublicKey.parse() also accepts raw hex and nostr: URIs - reject those
    # explicitly here so a caller that means to decode a UI-supplied npub
    # can't silently succeed on the wrong kind of input.
    if not npub.startswith("npub1"):
        raise ValueError("not a valid npub (must start with 'npub1')")
    try:
        return PublicKey.parse(npub).to_hex()
    except Exception as e:
        raise ValueError(f"not a valid npub: {e}") from e


def hex_to_npub(pubkey_hex: str) -> str:
    try:
        return PublicKey.parse(pubkey_hex).to_bech32()
    except Exception as e:
        raise ValueError(f"not a valid hex pubkey: {e}") from e


def parse_to_hex(value: str) -> str:
    """Accept either an npub or a raw hex pubkey and return canonical hex.

    For admin_cli.py (PLAN.md Phase 14/5's admin-provisioned linking): an
    admin pasting in an agent-reported public key shouldn't have to know or
    care which form it's in.
    """
    try:
        return PublicKey.parse(value).to_hex()
    except Exception as e:
        raise ValueError(f"not a valid npub or hex pubkey: {e}") from e
