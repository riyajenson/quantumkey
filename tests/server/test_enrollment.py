"""R-02: first registration requires a single-use invite bound to the username."""

import hashlib
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from quantumkey import crypto
from quantumkey.protocol.message import Operation
from quantumkey.server.app import create_app
from quantumkey.server.models import EnrollmentInvite
from quantumkey.server.service import INVITE_TTL, ProtocolError
from tests.helpers import RP_ID, FakeClock, database_url, message, new_cred


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def client(tmp_path, clock):
    return TestClient(create_app(database_url(tmp_path), rp_id=RP_ID, clock=clock))


def rp(client):
    return client.app.state.rp


def start(client, username, invite):
    return client.post("/auth/register/start", json={"username": username, "invite": invite})


def complete(client, started, cred, signature=None):
    if signature is None:
        signature = crypto.sign(
            cred.algorithm,
            cred.private_key,
            message(
                Operation.REGISTER, started, cred, extra=hashlib.sha256(cred.public_key).digest()
            ),
        )
    return client.post(
        "/auth/register/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": cred.credential_id,
            "public_key": crypto.b64e(cred.public_key),
            "policy": crypto.b64e(cred.policy.canonical_bytes()),
            "signature": crypto.b64e(signature),
        },
    )


def test_valid_invite_registers(client):
    invite = rp(client).issue_invite("alice")
    started = start(client, "alice", invite)
    assert started.status_code == 200, started.text
    assert complete(client, started.json(), new_cred()).status_code == 201


def test_missing_invite_is_a_schema_error(client):
    assert client.post("/auth/register/start", json={"username": "alice"}).status_code == 422


def test_empty_invite_is_a_schema_error(client):
    assert start(client, "alice", "").status_code == 422


def test_unknown_invite_is_rejected(client):
    rp(client).issue_invite("alice")
    response = start(client, "alice", "not-a-real-invite")
    assert (response.status_code, response.json()) == (403, {"error": "invalid_invite"})


def test_invite_is_bound_to_its_username(client):
    invite = rp(client).issue_invite("alice")
    response = start(client, "mallory", invite)
    assert (response.status_code, response.json()) == (403, {"error": "invalid_invite"})


def test_expired_invite_is_rejected(client, clock):
    invite = rp(client).issue_invite("alice")
    clock.now += INVITE_TTL + 1
    assert start(client, "alice", invite).status_code == 403


def test_default_invite_lifetime_is_24_hours():
    assert INVITE_TTL == 24 * 60 * 60


def test_invite_cannot_be_used_twice(client):
    invite = rp(client).issue_invite("alice")
    assert complete(client, start(client, "alice", invite).json(), new_cred()).status_code == 201
    assert start(client, "alice", invite).status_code == 403


def test_failed_signature_does_not_spend_the_invite(client):
    invite = rp(client).issue_invite("alice")
    cred = new_cred()
    bad = complete(client, start(client, "alice", invite).json(), cred, signature=b"\x00" * 3309)
    assert bad.status_code == 401
    assert complete(client, start(client, "alice", invite).json(), cred).status_code == 201


def test_invite_expiring_after_start_cannot_complete(client, clock):
    invite = rp(client).issue_invite("alice", ttl=30)
    started = start(client, "alice", invite).json()
    clock.now += 31  # challenge (60 s) is still live, the invite is not
    response = complete(client, started, new_cred())
    assert (response.status_code, response.json()) == (403, {"error": "invalid_invite"})


def test_username_existence_is_hidden_without_an_invite(client):
    complete(client, start(client, "alice", rp(client).issue_invite("alice")).json(), new_cred())
    # Without a valid invite for the name, a taken name looks like any other refusal.
    assert start(client, "alice", "guess").status_code == 403


def test_spare_invite_for_a_registered_user_reports_user_exists(client):
    first, spare = rp(client).issue_invite("alice"), rp(client).issue_invite("alice")
    assert complete(client, start(client, "alice", first).json(), new_cred()).status_code == 201
    assert start(client, "alice", spare).status_code == 409


def test_cannot_issue_an_invite_for_an_existing_user(client):
    assert complete(
        client, start(client, "alice", rp(client).issue_invite("alice")).json(), new_cred()
    ).status_code == 201
    with pytest.raises(ProtocolError) as error:
        rp(client).issue_invite("alice")
    assert error.value.code == "user_exists"


def test_only_the_token_hash_is_stored(client):
    invite = rp(client).issue_invite("alice")
    with Session(rp(client).engine) as session:
        row = session.scalars(select(EnrollmentInvite)).one()
    assert row.token_hash == hashlib.sha256(invite.encode()).digest()
    assert invite.encode() not in (row.token_hash, row.invite_id.encode(), row.username.encode())


def test_concurrent_completions_with_one_invite_allow_exactly_one(client):
    invite = rp(client).issue_invite("alice")
    attempts = [(start(client, "alice", invite).json(), new_cred()) for _ in range(8)]
    statuses = []
    barrier = threading.Barrier(len(attempts))

    def attempt(started, cred):
        barrier.wait()
        statuses.append(complete(client, started, cred).status_code)

    threads = [threading.Thread(target=attempt, args=pair) for pair in attempts]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(statuses) == [201] + [403] * 7

