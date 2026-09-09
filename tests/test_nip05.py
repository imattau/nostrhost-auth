from __future__ import annotations

from nostrhost_auth.identity.mappings import MappingStore
from nostrhost_auth.nip05 import build_nostr_json


class _FakeMapping:
    def __init__(self, store: MappingStore):
        self._store = store

    def get_by_username(self, username: str):
        return self._store.get_by_username(username)


def test_unknown_name_yields_empty(tmp_path):
    store = MappingStore(tmp_path / "mappings.db")
    assert build_nostr_json(_FakeMapping(store), "nobody") == {"names": {}}


def test_returns_pubkey_for_linked_username(tmp_path):
    store = MappingStore(tmp_path / "mappings.db")
    store.add_identity("alice", "f" * 64, signer_type="nip07")
    assert build_nostr_json(_FakeMapping(store), "alice") == {"names": {"alice": "f" * 64}}


def test_no_name_query_yields_empty(tmp_path):
    store = MappingStore(tmp_path / "mappings.db")
    store.add_identity("alice", "f" * 64, signer_type="nip07")
    assert build_nostr_json(_FakeMapping(store), None) == {"names": {}}


def test_revoked_identity_withheld(tmp_path):
    store = MappingStore(tmp_path / "mappings.db")
    identity = store.add_identity("alice", "f" * 64, signer_type="nip07")
    store.revoke_identity(identity.identity_id, "alice")
    assert build_nostr_json(_FakeMapping(store), "alice") == {"names": {}}