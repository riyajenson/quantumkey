"""T-15: login creates a server-side session that can be checked and ended."""

import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from quantumkey.server.app import create_app
from quantumkey.server.models import AuthSession
from quantumkey.server.service import SESSION_TTL
from tests.helpers import (
    RP_ID,
    FakeClock,
    database_url,
    login_body,
    login_signature,
    migrate_body,
    migration_signatures,
    new_cred,
    register,
)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def client(tmp_path, clock):
    return TestClient(create_app(database_url(tmp_path), rp_id=RP_ID, clock=clock))


def login(client, username, cred):
    started = client.post(
        "/auth/login/start", json={"username": username, "credential_id": cred.credential_id}
    ).json()
    response = client.post(
        "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
    )
    assert response.status_code == 200, response.text
    return response.json()["session_token"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}




def test_session_ttl_default():
    assert SESSION_TTL == 60 * 60


def test_login_creates_a_session_the_server_recognizes(client):
    cred = register(client, "alice")
    token = login(client, "alice", cred)
    response = client.get("/auth/session", headers=bearer(token))
    assert response.status_code == 200
    body = response.json()
    assert (body["username"], body["credential_id"]) == ("alice", cred.credential_id)


def test_only_the_token_hash_is_stored(client):
    cred = register(client, "alice")
    token = login(client, "alice", cred)
    with Session(client.app.state.rp.engine) as session:
        row = session.scalars(select(AuthSession)).one()
    assert row.token_hash == hashlib.sha256(token.encode()).digest()


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic abc"}]
)
def test_missing_or_unknown_token_is_401(client, headers):
    response = client.get("/auth/session", headers=headers)
    assert (response.status_code, response.json()) == (401, {"error": "invalid_session"})


def test_session_expires(client, clock):
    cred = register(client, "alice")
    token = login(client, "alice", cred)
    clock.now += SESSION_TTL + 1
    assert client.get("/auth/session", headers=bearer(token)).status_code == 401


def test_logout_ends_the_session(client):
    cred = register(client, "alice")
    token = login(client, "alice", cred)
    assert client.post("/auth/logout", json={}, headers=bearer(token)).status_code == 200
    assert client.get("/auth/session", headers=bearer(token)).status_code == 401
    assert client.post("/auth/logout", json={}, headers=bearer(token)).status_code == 401








def test_sessions_are_independent(client):
    alice, bob = register(client, "alice"), register(client, "bob")
    token_alice, token_bob = login(client, "alice", alice), login(client, "bob", bob)
    assert token_alice != token_bob
    client.post("/auth/logout", json={}, headers=bearer(token_alice))
    assert client.get("/auth/session", headers=bearer(token_bob)).json()["username"] == "bob"


def test_migration_ends_the_old_credentials_sessions(client):
    old = register(client, "alice")
    token = login(client, "alice", old)
    new = new_cred()
    started = client.post(
        "/auth/migrate/start", json={"username": "alice", "credential_id": old.credential_id}
    ).json()
    old_sig, new_sig = migration_signatures(started, old, new)
    assert client.post(
        "/auth/migrate/complete", json=migrate_body(started, new, old_sig, new_sig)
    ).status_code == 200
    assert client.get("/auth/session", headers=bearer(token)).status_code == 401
