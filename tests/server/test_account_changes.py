"""ADR 0009: an existing credential authorizes enrolling another credential
(the account then has both) and revoking one of the account's credentials."""

import pytest
from fastapi.testclient import TestClient

from quantumkey.protocol.message import Operation
from quantumkey.protocol.policy import Policy
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
from quantumkey.server.app import create_app


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(database_url(tmp_path), rp_id=RP_ID, clock=FakeClock()))


def enroll_body(started, new, authorizer_sig, new_sig, device_id=None):
    body = migrate_body(started, new, authorizer_sig, new_sig)
    body["authorizer_signature"] = body.pop("old_signature")
    if device_id:
        body["new_device_id"] = device_id
    return body


def enroll(client, username, authorizer, new=None, operation=Operation.ENROLL):
    new = new or new_cred()
    started = client.post(
        "/auth/enroll/start", json={"username": username, "credential_id": authorizer.credential_id}
    )
    assert started.status_code == 200, started.text
    started = started.json()
    signatures = migration_signatures(started, authorizer, new, operation)
    return new, client.post("/auth/enroll/complete", json=enroll_body(started, new, *signatures))


def can_login(client, username, cred):
    started = client.post(
        "/auth/login/start", json={"username": username, "credential_id": cred.credential_id}
    )
    if started.status_code != 200:
        return False
    started = started.json()
    response = client.post(
        "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
    )
    return response.status_code == 200


def status(client, cred):
    return client.get(f"/credentials/{cred.credential_id}").json()["status"]


# -- enroll ----------------------------------------------------------------------


def test_enroll_adds_a_second_active_credential(client):
    first = register(client, "alice")
    second, response = enroll(client, "alice", first)
    assert (response.status_code, response.json()) == (
        200,
        {"credential_id": second.credential_id, "status": "active"},
    )
    assert status(client, first) == status(client, second) == "active"
    assert can_login(client, "alice", first) and can_login(client, "alice", second)


def test_a_migrate_signature_cannot_enroll(client):
    first = register(client, "alice")
    _, response = enroll(client, "alice", first, operation=Operation.MIGRATE)
    assert (response.status_code, response.json()) == (401, {"error": "invalid_signature"})


def test_an_enroll_signature_cannot_migrate(client):
    first = register(client, "alice")
    new = new_cred()
    started = client.post(
        "/auth/migrate/start", json={"username": "alice", "credential_id": first.credential_id}
    ).json()
    old_sig, new_sig = migration_signatures(started, first, new, Operation.ENROLL)
    response = client.post("/auth/migrate/complete", json=migrate_body(started, new, old_sig, new_sig))
    assert response.status_code == 401
    assert status(client, first) == "active"


def test_authorizer_policy_without_enroll_is_refused(client):
    first = register(client, "alice", new_cred(policy=Policy(rp_id=RP_ID, allowed_ops=("register", "login"))))
    _, response = enroll(client, "alice", first)
    assert (response.status_code, response.json()) == (403, {"error": "policy_violation"})


def test_enroll_start_rejects_another_users_credential(client):
    register(client, "alice")
    bob = register(client, "bob")
    response = client.post(
        "/auth/enroll/start", json={"username": "alice", "credential_id": bob.credential_id}
    )
    assert response.status_code == 404


def test_enroll_records_the_new_device(client):
    first = register(client, "alice")
    new = new_cred()
    started = client.post(
        "/auth/enroll/start", json={"username": "alice", "credential_id": first.credential_id}
    ).json()
    body = enroll_body(started, new, *migration_signatures(started, first, new, Operation.ENROLL), "qkd-" + "1" * 32)
    assert client.post("/auth/enroll/complete", json=body).status_code == 200
    assert client.get(f"/credentials/{new.credential_id}").json()["device_id"] == "qkd-" + "1" * 32


def test_enroll_cannot_reuse_a_credential_id(client):
    first = register(client, "alice")
    _, response = enroll(client, "alice", first, new=new_cred())
    duplicate = new_cred()
    object.__setattr__(duplicate, "credential_id", first.credential_id)
    _, response = enroll(client, "alice", first, new=duplicate)
    assert response.status_code == 409
