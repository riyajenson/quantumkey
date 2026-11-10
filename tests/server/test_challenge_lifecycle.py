"""Phase 3 gate: expiry, replay, mismatch, tampering, and concurrency."""

import threading

import pytest
from fastapi.testclient import TestClient

from quantumkey import crypto
from quantumkey.protocol.policy import Policy
from quantumkey.server.app import create_app
from tests.helpers import (
    RP_ID,
    FakeClock,
    database_url,
    login_body,
    login_signature,
    new_cred,
    register,
    start_registration,
)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def client(tmp_path, clock):
    app = create_app(
        database_url(tmp_path),
        rp_id=RP_ID,
        clock=clock,
        challenge_ttl=60,
    )
    return TestClient(app)


def start_login(client, username="alice", credential_id=None):
    body = {"username": username}
    if credential_id:
        body["credential_id"] = credential_id
    response = client.post("/auth/login/start", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_register_then_login_succeeds_repeatedly(client):
    cred = register(client, "alice")
    for _ in range(3):
        started = start_login(client)
        response = client.post(
            "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
        )
        assert response.status_code == 200
        assert response.json()["authenticated"] is True


def test_replayed_login_is_rejected(client):
    cred = register(client, "alice")
    started = start_login(client)
    body = login_body(started, cred, login_signature(started, cred))
    assert client.post("/auth/login/complete", json=body).status_code == 200
    replay = client.post("/auth/login/complete", json=body)
    assert replay.status_code == 400
    assert replay.json() == {"error": "invalid_challenge"}


def test_expired_challenge_is_rejected(client, clock):
    cred = register(client, "alice")
    started = start_login(client)
    clock.now += 61
    response = client.post(
        "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_challenge"}


def test_altered_signature_fails_and_burns_the_challenge(client):
    cred = register(client, "alice")
    started = start_login(client)
    signature = bytearray(login_signature(started, cred))
    signature[10] ^= 0x01
    response = client.post(
        "/auth/login/complete", json=login_body(started, cred, bytes(signature))
    )
    assert response.status_code == 401
    # The same challenge cannot be retried with the correct signature.
    retry = client.post(
        "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
    )
    assert retry.status_code == 400


def test_signature_from_another_credential_fails(client):
    register(client, "alice")
    mallory = new_cred()
    started = start_login(client)
    response = client.post(
        "/auth/login/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": started["credential_id"],
            "signature": crypto.b64e(login_signature(started, mallory)),
        },
    )
    assert response.status_code == 401


def test_credential_id_mismatch_is_rejected(client):
    cred = register(client, "alice")
    other = register(client, "bob")
    started = start_login(client, "alice")
    response = client.post(
        "/auth/login/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": other.credential_id,
            "signature": crypto.b64e(login_signature(started, cred)),
        },
    )
    assert response.status_code == 400
    assert response.json() == {"error": "credential_mismatch"}


def test_challenge_is_bound_to_its_purpose(client):
    cred = register(client, "alice")
    started = start_registration(client, "carol").json()
    response = client.post(
        "/auth/login/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": cred.credential_id,
            "signature": crypto.b64e(b"x"),
        },
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_challenge"}


def test_signature_for_another_relying_party_is_rejected(client):
    from quantumkey.protocol.message import Operation
    from tests.helpers import message

    cred = register(client, "alice")
    started = start_login(client)
    forged = crypto.sign(
        cred.algorithm,
        cred.private_key,
        message(Operation.LOGIN, started, cred, rp_id="evil.example"),
    )
    response = client.post("/auth/login/complete", json=login_body(started, cred, forged))
    assert response.status_code == 401


def test_registration_rejects_swapped_policy(client):
    cred = new_cred()
    started = start_registration(client, "alice").json()
    from quantumkey.protocol.message import Operation
    import hashlib
    from tests.helpers import message

    signature = crypto.sign(
        cred.algorithm,
        cred.private_key,
        message(Operation.REGISTER, started, cred, extra=hashlib.sha256(cred.public_key).digest()),
    )
    weaker = Policy(rp_id=RP_ID, allowed_ops=("register", "login", "migrate"), max_signs_per_minute=999)
    response = client.post(
        "/auth/register/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": cred.credential_id,
            "public_key": crypto.b64e(cred.public_key),
            "policy": crypto.b64e(weaker.canonical_bytes()),
            "signature": crypto.b64e(signature),
        },
    )
    assert response.status_code == 401


def test_policy_for_wrong_rp_is_rejected(client):
    cred = new_cred(policy=Policy(rp_id="evil.example"))
    started = start_registration(client, "alice").json()
    response = client.post(
        "/auth/register/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": cred.credential_id,
            "public_key": crypto.b64e(cred.public_key),
            "policy": crypto.b64e(cred.policy.canonical_bytes()),
            "signature": crypto.b64e(b"x"),
        },
    )
    assert response.status_code == 422


def test_duplicate_user_and_unknown_user(client):
    spare = client.app.state.rp.issue_invite("alice")
    register(client, "alice")
    assert (
        client.post("/auth/register/start", json={"username": "alice", "invite": spare}).status_code
        == 409
    )
    assert client.post("/auth/login/start", json={"username": "nobody"}).status_code == 404


def test_malformed_input_is_rejected(client):
    started = start_registration(client, "alice").json()
    base = {
        "transaction_id": started["transaction_id"],
        "credential_id": "c",
        "public_key": "AA==",  # padded: non-canonical
        "policy": "AA",
        "signature": "AA",
    }
    assert client.post("/auth/register/complete", json=base).status_code == 422
    assert (
        client.post(
            "/auth/register/start", json={"username": "x", "invite": "i", "algorithm": "RSA"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/auth/register/start", json={"username": "x", "invite": "i", "extra": 1}
        ).status_code
        == 422
    )


def test_concurrent_completion_allows_exactly_one_success(client):
    cred = register(client, "alice")
    started = start_login(client)
    signature = login_signature(started, cred)
    rp = client.app.state.rp
    results = []

    def attempt():
        try:
            rp.login_complete(started["transaction_id"], cred.credential_id, signature)
            results.append("ok")
        except Exception as exc:  # noqa: BLE001 - recording every outcome
            results.append(type(exc).__name__)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("ok") == 1
    assert len(results) == 8
