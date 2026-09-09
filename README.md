# nostrhost-auth

Reusable authentication/identity library for the [nostrhost](../) Nostr-native
YunoHost derivative. Extracted from the reference implementation
[`yunohost-nostr-auth`](https://github.com/imattau/yunohost-nostr-auth) (the
standalone add-on service that still ships for stock YunoHost via
[`nostr_auth_ynh`](https://github.com/imattau/nostr_auth_ynh) — which remains
operational during this migration).

## What it provides

Framework-free, transport-free core components:

| module | provides |
|---|---|
| `auth.challenge` | single-use, domain/action-bound challenge issuance + atomic sqlite-backed `ChallengeStore` |
| `auth.nostr_verify` | NIP-01 parse + BIP-340 signature verification, challenge-response binding (kind 22242) |
| `identity.npub` | npub ↔ hex conversion (UI boundary only; internal code deals in hex) |
| `identity.mappings` | pubkey ↔ username `MappingStore` (sqlite), linking semantics, legacy migration |
| `identity.relays` | NIP-65 (kind 10002) relay-list resolution over nostr-sdk's relay pool |
| `identity.relay_cache` | sqlite-backed relay-list cache |
| `nip05` | NIP-05 `.well-known/nostr.json` builder |
| `web` | static `/nostr-login` `/nostr-account` `/nostr-admin` pages + JS assets (NIP-07, NIP-46, passkey) |

Crypto is delegated to `nostr-sdk` (rust-nostr) exactly as the reference does;
never accepts or stores a private key.

## Explicitly not here (yet)

The reference's YunoHost-coupling layer (`ynh/`: session minting, portal
cookie/client, LDAP lookup, privilege helpers) and its HTTP daemon
(`server.py`, `admin_cli.py`) stay in the reference implementation until the
derivative's native identity API and session creation land (roadmap stages
3–5). `identity/linking.py` is likewise re-homed there once the native
identity API provides its own session-confirmation boundary.

## Development

```
uv sync --all-groups
uv run pytest
```