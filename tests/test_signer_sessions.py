import pytest

from nostrhost_auth.identity.signer_sessions import SignerSessionStore

BUNKER_PUBKEY_A = "a" * 64
BUNKER_PUBKEY_B = "b" * 64


@pytest.fixture
def store(tmp_path):
    return SignerSessionStore(tmp_path / "signer_sessions.db")


def test_register_then_list(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, '["wss://relay.example"]', label="Phone")

    sessions = store.list_by_username("matt")
    assert len(sessions) == 1
    assert sessions[0].session_id == "sess-1"
    assert sessions[0].bunker_pubkey == BUNKER_PUBKEY_A
    assert sessions[0].label == "Phone"
    assert sessions[0].revoked_at is None


def test_list_only_returns_own_username(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, "[]")
    store.register("sess-2", "alice", BUNKER_PUBKEY_B, "[]")

    assert [s.session_id for s in store.list_by_username("matt")] == ["sess-1"]
    assert [s.session_id for s in store.list_by_username("alice")] == ["sess-2"]


def test_re_register_same_session_id_refreshes_it(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, '["wss://a"]', label="First")
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, '["wss://b"]', label="Renamed")

    sessions = store.list_by_username("matt")
    assert len(sessions) == 1
    assert sessions[0].relays == '["wss://b"]'
    assert sessions[0].label == "Renamed"


def test_session_id_cannot_be_stolen_by_another_user(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, "[]")

    with pytest.raises(ValueError):
        store.register("sess-1", "alice", BUNKER_PUBKEY_B, "[]")


def test_revoke_hides_session_from_default_listing(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, "[]")

    assert store.revoke("sess-1", "matt") is True
    assert store.list_by_username("matt") == []
    assert len(store.list_by_username("matt", include_revoked=True)) == 1


def test_revoke_only_affects_the_owning_user(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, "[]")

    assert store.revoke("sess-1", "alice") is False
    assert len(store.list_by_username("matt")) == 1


def test_revoke_twice_is_a_no_op(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, "[]")

    assert store.revoke("sess-1", "matt") is True
    assert store.revoke("sess-1", "matt") is False


def test_delete_all_for_username(store):
    store.register("sess-1", "matt", BUNKER_PUBKEY_A, "[]")
    store.register("sess-2", "matt", BUNKER_PUBKEY_B, "[]")
    store.register("sess-3", "alice", BUNKER_PUBKEY_B, "[]")

    assert store.delete_all_for_username("matt") == 2
    assert store.list_by_username("matt", include_revoked=True) == []
    assert len(store.list_by_username("alice")) == 1
