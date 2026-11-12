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


# -- revoke ----------------------------------------------------------------------


def revoke(client, username, authorizer, target_id, signed_target=None):
    from quantumkey import crypto
    from quantumkey.protocol.migration import revocation_binding
    from tests.helpers import message

    started = client.post(
        "/auth/revoke/start", json={"username": username, "credential_id": authorizer.credential_id}
    )
    if started.status_code != 200:
        return started
    started = started.json()
    binding = revocation_binding(signed_target if signed_target is not None else target_id)
    signature = crypto.sign(
        authorizer.algorithm, authorizer.private_key,
        message(Operation.REVOKE, started, authorizer, extra=binding),
    )
    return client.post(
        "/auth/revoke/complete",
        json={
            "transaction_id": started["transaction_id"],
            "target_credential_id": target_id,
            "signature": crypto.b64e(signature),
        },
    )


def two_device_account(client, username="alice"):
    first = register(client, username)
    second, response = enroll(client, username, first)
    assert response.status_code == 200
    return first, second


def test_a_device_revokes_another_lost_device(client):
    first, lost = two_device_account(client)
    response = revoke(client, "alice", first, lost.credential_id)
    assert (response.status_code, response.json()) == (
        200,
        {"credential_id": lost.credential_id, "status": "revoked"},
    )
    assert status(client, lost) == "revoked" and not can_login(client, "alice", lost)
    assert can_login(client, "alice", first)


def test_a_device_may_revoke_itself_if_another_remains(client):
    first, second = two_device_account(client)
    assert revoke(client, "alice", first, first.credential_id).status_code == 200
    assert status(client, first) == "revoked" and status(client, second) == "active"


def test_the_last_active_credential_cannot_be_revoked(client):
    only = register(client, "alice")
    response = revoke(client, "alice", only, only.credential_id)
    assert (response.status_code, response.json()) == (409, {"error": "last_credential"})
    assert status(client, only) == "active"


def test_another_accounts_credential_cannot_be_revoked(client):
    first, _ = two_device_account(client, "alice")
    bob_first, bob_second = two_device_account(client, "bob")
    response = revoke(client, "alice", first, bob_second.credential_id)
    assert (response.status_code, response.json()) == (404, {"error": "unknown_credential"})
    assert status(client, bob_second) == "active"


def test_signature_for_another_target_is_rejected(client):
    first, second = two_device_account(client)
    third, _ = enroll(client, "alice", first)
    response = revoke(client, "alice", first, third.credential_id, signed_target=second.credential_id)
    assert (response.status_code, response.json()) == (401, {"error": "invalid_signature"})
    assert status(client, second) == status(client, third) == "active"


def test_authorizer_policy_without_revoke_is_refused(client):
    limited = new_cred(policy=Policy(rp_id=RP_ID, allowed_ops=("register", "login", "enroll")))
    first = register(client, "alice", limited)
    second, _ = enroll(client, "alice", first)
    response = revoke(client, "alice", first, second.credential_id)
    assert (response.status_code, response.json()) == (403, {"error": "policy_violation"})


def test_revoking_ends_the_targets_sessions(client):
    first, second = two_device_account(client)
    started = client.post(
        "/auth/login/start", json={"username": "alice", "credential_id": second.credential_id}
    ).json()
    token = client.post(
        "/auth/login/complete", json=login_body(started, second, login_signature(started, second))
    ).json()["session_token"]
    assert revoke(client, "alice", first, second.credential_id).status_code == 200
    assert client.get("/auth/session", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_concurrent_mutual_revocation_leaves_exactly_one_active_credential(client):
    import threading

    for attempt in range(5):
        username = f"user{attempt}"
        first, second = two_device_account(client, username)
        statuses, barrier = [], threading.Barrier(2)

        def attempt_revoke(authorizer, target):
            barrier.wait()
            statuses.append(revoke(client, username, authorizer, target.credential_id).status_code)

        threads = [
            threading.Thread(target=attempt_revoke, args=(first, second)),
            threading.Thread(target=attempt_revoke, args=(second, first)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert statuses.count(200) == 1, statuses
        assert [status(client, c) for c in (first, second)].count("active") == 1


# -- recovery credentials ------------------------------------------------------------

RECOVERY = ("register", "enroll", "revoke")


def test_default_login_skips_credentials_that_may_not_log_in(client):
    recovery = register(client, "alice", new_cred(policy=Policy(rp_id=RP_ID, allowed_ops=RECOVERY)))
    daily, response = enroll(client, "alice", recovery)
    assert response.status_code == 200
    started = client.post("/auth/login/start", json={"username": "alice"}).json()
    assert started["credential_id"] == daily.credential_id
    assert can_login(client, "alice", daily)


def test_recovery_credential_cannot_log_in_even_when_named(client):
    recovery = register(client, "alice", new_cred(policy=Policy(rp_id=RP_ID, allowed_ops=RECOVERY)))
    assert not can_login(client, "alice", recovery)


def test_account_with_only_a_recovery_credential_has_no_default_login(client):
    register(client, "alice", new_cred(policy=Policy(rp_id=RP_ID, allowed_ops=RECOVERY)))
    response = client.post("/auth/login/start", json={"username": "alice"})
    assert (response.status_code, response.json()) == (404, {"error": "unknown_credential"})


# -- listing the account's credentials -------------------------------------------------


def session_for(client, username, cred):
    started = client.post(
        "/auth/login/start", json={"username": username, "credential_id": cred.credential_id}
    ).json()
    response = client.post(
        "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
    )
    return {"Authorization": f"Bearer {response.json()['session_token']}"}


def test_a_session_lists_the_accounts_credentials(client):
    first, second = two_device_account(client)
    third, _ = enroll(client, "alice", first)
    assert revoke(client, "alice", first, third.credential_id).status_code == 200
    response = client.get("/auth/credentials", headers=session_for(client, "alice", second))
    assert response.status_code == 200
    listed = response.json()["credentials"]
    # The fixture's clock is fixed, so creation times tie; compare as a set.
    assert {(c["credential_id"], c["status"]) for c in listed} == {
        (first.credential_id, "active"),
        (second.credential_id, "active"),
        (third.credential_id, "revoked"),
    }
    assert set(listed[0]) == {
        "credential_id", "status", "algorithm", "device_id", "allowed_ops", "created_at", "replaced_by"
    }
    assert set(listed[0]["allowed_ops"]) == {"register", "login", "migrate", "enroll", "revoke"}


def test_listing_shows_only_the_sessions_account(client):
    alice_first, _ = two_device_account(client, "alice")
    register(client, "bob")
    listed = client.get("/auth/credentials", headers=session_for(client, "alice", alice_first)).json()
    assert len(listed["credentials"]) == 2


def test_listing_needs_a_session(client):
    two_device_account(client)
    response = client.get("/auth/credentials")
    assert (response.status_code, response.json()) == (401, {"error": "invalid_session"})
