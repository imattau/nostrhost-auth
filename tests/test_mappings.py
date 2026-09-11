import pytest

from nostrhost_auth.identity.mappings import MappingStore, PubkeyAlreadyLinked

PUBKEY_A = "a" * 64
PUBKEY_B = "b" * 64


@pytest.fixture
def store(tmp_path):
    return MappingStore(tmp_path / "identities.db")


def test_link_then_lookup(store):
    store.link("matt", PUBKEY_A)

    identity = store.get_by_pubkey(PUBKEY_A)
    assert identity is not None
    assert identity.ynh_username == "matt"
    assert identity.enabled

    assert store.get_by_username("matt").pubkey == PUBKEY_A


def test_unknown_pubkey_returns_none(store):
    assert store.get_by_pubkey(PUBKEY_A) is None
    assert store.get_by_username("matt") is None


def test_replacing_own_identity_is_allowed(store):
    store.link("matt", PUBKEY_A)
    store.link("matt", PUBKEY_B)

    assert store.get_by_pubkey(PUBKEY_A) is None
    assert store.get_by_pubkey(PUBKEY_B).ynh_username == "matt"


def test_pubkey_cannot_be_claimed_by_a_second_user(store):
    store.link("matt", PUBKEY_A)

    with pytest.raises(PubkeyAlreadyLinked):
        store.link("alice", PUBKEY_A)

    # Original mapping is untouched.
    assert store.get_by_pubkey(PUBKEY_A).ynh_username == "matt"


def test_unlink_removes_mapping(store):
    store.link("matt", PUBKEY_A)
    assert store.unlink("matt") == 1

    assert store.get_by_pubkey(PUBKEY_A) is None
    assert store.get_by_username("matt") is None


def test_unlink_missing_user_reports_zero_rows(store):
    assert store.unlink("nobody") == 0


def test_touch_last_used(store):
    store.link("matt", PUBKEY_A)
    assert store.get_by_username("matt").last_used is None

    store.touch_last_used("matt")
    assert store.get_by_username("matt").last_used is not None


def test_list_all(store):
    store.link("matt", PUBKEY_A)
    store.link("alice", PUBKEY_B)

    usernames = [identity.ynh_username for identity in store.list_all()]
    assert usernames == ["alice", "matt"]


def test_reopening_store_persists_data(tmp_path):
    db_path = tmp_path / "identities.db"
    MappingStore(db_path).link("matt", PUBKEY_A)

    reopened = MappingStore(db_path)
    assert reopened.get_by_username("matt").pubkey == PUBKEY_A


def test_multiple_identities_can_belong_to_one_user(store):
    first = store.add_identity("matt", PUBKEY_A, signer_type="nip07", label="Laptop")
    second = store.add_identity("matt", PUBKEY_B, signer_type="nip46", label="Phone")

    assert first.identity_id != second.identity_id
    assert [identity.pubkey for identity in store.list_by_username("matt")] == [PUBKEY_B, PUBKEY_A]
    assert store.get_by_pubkey(PUBKEY_A).label == "Laptop"
    assert store.get_by_pubkey(PUBKEY_B).signer_type == "nip46"


def test_identity_can_be_revoked_without_removing_other_identities(store):
    first = store.add_identity("matt", PUBKEY_A, label="Laptop")
    second = store.add_identity("matt", PUBKEY_B, label="Phone")

    assert store.revoke_identity(first.identity_id, "matt") is True
    assert store.get_by_pubkey(PUBKEY_A) is None
    assert store.get_by_pubkey(PUBKEY_B) is not None
    assert store.get_by_id(first.identity_id).revoked_at is not None
    assert store.revoke_identity(second.identity_id, "alice") is False


def test_active_identity_label_can_be_updated_without_changing_pubkey(store):
    identity = store.add_identity("matt", PUBKEY_A, label="Laptop")

    updated = store.update_identity_label(identity.identity_id, "matt", "Work laptop")

    assert updated.label == "Work laptop"
    assert updated.pubkey == PUBKEY_A
    assert store.update_identity_label(identity.identity_id, "alice", "Nope") is None


def test_active_identity_profile_can_be_updated(store):
    identity = store.add_identity("matt", PUBKEY_A, signer_type="nip07", label="Laptop")

    updated = store.update_identity_profile(
        identity.identity_id, "matt", signer_type="nip46", label="Phone"
    )

    assert updated is not None
    assert updated.signer_type == "nip46"
    assert updated.label == "Phone"
    # ownership is enforced: another user cannot mutate the row
    assert store.update_identity_profile(identity.identity_id, "alice", signer_type="nip46", label="x") is None
    # a revoked identity is not profile-updated in place
    store.revoke_identity(identity.identity_id, "matt")
    assert store.update_identity_profile(identity.identity_id, "matt", signer_type="nip07", label="y") is None


def test_legacy_users_table_is_migrated_once(tmp_path):
    import sqlite3

    db_path = tmp_path / "identities.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE users (
                ynh_username TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL,
                last_used INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)", ("matt", PUBKEY_A, 1, None, 1))
        conn.commit()

    store = MappingStore(db_path)
    assert store.get_by_pubkey(PUBKEY_A).ynh_username == "matt"

    store.link("matt", PUBKEY_B)
    reopened = MappingStore(db_path)
    assert [identity.pubkey for identity in reopened.list_by_username("matt")] == [PUBKEY_B]


def test_set_identity_enabled_reenables(tmp_path):
    store = MappingStore(tmp_path / "mappings.db")
    identity = store.add_identity("alice", "f" * 64, signer_type="nip07")
    assert store.revoke_identity(identity.identity_id, "alice")
    # disabled identity is not resolvable
    assert store.get_by_pubkey("f" * 64) is None
    # but the projector can re-enable it
    assert store.set_identity_enabled(identity.identity_id, "alice", True)
    assert store.get_by_pubkey("f" * 64) is not None
    # and look it up regardless of state
    assert store.get_identity_by_pubkey("f" * 64) is not None
