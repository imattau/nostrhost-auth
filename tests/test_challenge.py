from concurrent.futures import ThreadPoolExecutor

from nostrhost_auth.auth.challenge import ChallengeStore


def test_challenge_is_single_use():
    store = ChallengeStore()
    challenge = store.issue(domain="example.org", action="yunohost-login")

    assert store.consume(challenge.nonce) is not None
    assert store.consume(challenge.nonce) is None


def test_unknown_nonce_is_rejected():
    store = ChallengeStore()
    assert store.consume("does-not-exist") is None


def test_persistent_challenge_survives_store_reopen(tmp_path):
    db_path = tmp_path / "challenges.db"
    first_store = ChallengeStore(db_path=db_path)
    challenge = first_store.issue(domain="example.org", action="yunohost-login")

    reopened_store = ChallengeStore(db_path=db_path)

    assert reopened_store.consume(challenge.nonce) == challenge
    assert reopened_store.consume(challenge.nonce) is None


def test_persistent_challenge_is_consumed_only_once_across_stores(tmp_path):
    db_path = tmp_path / "challenges.db"
    first_store = ChallengeStore(db_path=db_path)
    second_store = ChallengeStore(db_path=db_path)
    challenge = first_store.issue(domain="example.org", action="yunohost-login")

    assert first_store.consume(challenge.nonce) == challenge
    assert second_store.consume(challenge.nonce) is None


def test_persistent_challenge_is_consumed_once_under_concurrency(tmp_path):
    db_path = tmp_path / "challenges.db"
    issuing_store = ChallengeStore(db_path=db_path)
    challenge = issuing_store.issue(domain="example.org", action="yunohost-login")
    stores = [ChallengeStore(db_path=db_path), ChallengeStore(db_path=db_path)]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda store: store.consume(challenge.nonce), stores))

    assert sum(result is not None for result in results) == 1


def test_challenge_store_rejects_non_positive_ttl():
    try:
        ChallengeStore(ttl_seconds=0)
    except ValueError as exc:
        assert str(exc) == "ttl_seconds must be positive"
    else:  # pragma: no cover - assertion is clearer than pytest.raises here
        raise AssertionError("expected ValueError")


def test_challenge_store_keeps_positional_ttl_compatibility():
    store = ChallengeStore(12)
    assert store.issue(domain="example.org", action="yunohost-login").expires_at > 0
