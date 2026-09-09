"""NIP-05 (.well-known/nostr.json) builder.

Extracted from yunohost-nostr-auth's nostr_json_endpoint (server.py): the
pure, HTTP-free logic that turns a linked pubkey mapping into the NIP-05
response body, so any transport (the standalone daemon's Starlette route
today, the derivative's native identityd tomorrow) can reuse it.
"""

from __future__ import annotations

from typing import Protocol


class IdentityMapping(Protocol):
    """The minimal mapping-store surface NIP-05 needs."""

    def get_by_username(self, username: str):
        ...


def build_nostr_json(mappings: IdentityMapping, name: str | None) -> dict[str, dict[str, str]]:
    """Build a NIP-05 ``{"names": {<username>: <pubkey_hex>}}`` body.

    Only ever reveals a mapping for a username that has actually linked a
    pubkey (opt-in by definition of having linked one at all), and only
    when queried by that exact name - this never lists all linked users at
    once, matching how every other NIP-05 provider behaves. Disabled
    identities are withheld.

    ``name`` may be None (no ``?name=`` query param) -> empty ``names``.
    """
    names: dict[str, str] = {}
    if name:
        identity = mappings.get_by_username(name)
        if identity is not None and getattr(identity, "enabled", True):
            names[name] = identity.pubkey
    return {"names": names}