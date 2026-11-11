"""Phase 7: software -> virtual-token migration without exporting a private key."""

import io

import pytest
from fastapi.testclient import TestClient

from quantumkey import crypto
from quantumkey.authenticator import token as token_module
from quantumkey.authenticator.client import AuthClient, ServerRejected
from quantumkey.authenticator.core import SigningCore, SigningRefused
from quantumkey.authenticator.software import SoftwareSigner
from quantumkey.authenticator.token import VirtualToken, handle
from quantumkey.protocol.policy import Policy
from quantumkey.server.app import create_app
from tests.helpers import RP_ID, FakeClock, invite


@pytest.fixture
def http(tmp_path):
    app = create_app("sqlite:///" + (tmp_path / "rp.sqlite3").as_posix(), rp_id=RP_ID)
    return TestClient(app)


@pytest.fixture
def software(tmp_path):
    return SoftwareSigner(tmp_path / "vault.sqlite3", pin="1234")


@pytest.fixture
def token():
    with VirtualToken() as device:
        yield device


def test_token_registers_and_logs_in_like_software(http, token):
    client = AuthClient(http, RP_ID)
    credential_id = client.register("alice", token, invite=invite(http, "alice"))
    assert client.login("alice", token, credential_id)


@pytest.mark.parametrize("algorithm", crypto.ALGORITHMS)
def test_migration_software_to_token(http, software, token, algorithm):
    client = AuthClient(http, RP_ID)
    old_id = client.register("alice", software, invite=invite(http, "alice"))
    new_id = client.migrate("alice", old_id, software, token, algorithm=algorithm)

    assert http.get(f"/credentials/{old_id}").json() == {
        "credential_id": old_id,
        "status": "revoked",
        "replaced_by": new_id,
        "device_id": software.device_id,
    }
    assert http.get(f"/credentials/{new_id}").json()["status"] == "active"
    # The server completes login without knowing which backend signed.
    assert client.login("alice", token)
    # The old software credential is no longer accepted.
    with pytest.raises(ServerRejected):
        client.login("alice", software, old_id)


def test_migration_denied_when_policy_forbids_it(http, software, token):
    client = AuthClient(http, RP_ID)
    old_id = client.register(
        "alice", software, policy=Policy(rp_id=RP_ID, allowed_ops=("register", "login")),
        invite=invite(http, "alice"),
    )
    with pytest.raises(SigningRefused, match="not allowed"):
        client.migrate("alice", old_id, software, token)
    assert http.get(f"/credentials/{old_id}").json()["status"] == "active"
    assert client.login("alice", software, old_id)


def test_failed_migration_leaves_old_credential_usable(http, software, token):
    client = AuthClient(http, RP_ID)
    old_id = client.register("alice", software, invite=invite(http, "alice"))
    started = http.post(
        "/auth/migrate/start", json={"username": "alice", "credential_id": old_id}
    ).json()
    response = http.post(
        "/auth/migrate/complete",
        json={
            "transaction_id": started["transaction_id"],
            "new_credential_id": "qk-new",
            "new_public_key": crypto.b64e(b"\x00" * 1952),
            "new_policy": crypto.b64e(Policy(rp_id=RP_ID).canonical_bytes()),
            "old_signature": crypto.b64e(b"\x00" * 3309),
            "new_signature": crypto.b64e(b"\x00" * 3309),
        },
    )
    assert response.status_code == 401
    assert client.login("alice", software, old_id)


def test_token_has_no_export_or_raw_sign_command():
    core = SigningCore()
    core.create("ML-DSA-65", Policy(rp_id=RP_ID), "c1")
    for command in ("export", "export_secret_key", "sign_bytes", "dump"):
        assert handle(core, {"cmd": command, "credential_id": "c1"})["ok"] is False
    # A sign request may not carry caller-chosen message bytes.
    reply = handle(
        core,
        {
            "cmd": "sign",
            "credential_id": "c1",
            "operation": 2,
            "rp_id": RP_ID,
            "transaction_id": "tx",
            "challenge": crypto.b64e(b"\x00" * 32),
            "target": None,
            "message": crypto.b64e(b"attacker chosen bytes"),
        },
    )
    assert reply == {"ok": False, "error": "unexpected field"}


def test_token_enforces_policy_for_a_malicious_host(token):
    token.create_credential("ML-DSA-65", Policy(rp_id=RP_ID, allowed_ops=("login",)), "c1")
    from quantumkey.authenticator.core import SignRequest
    from quantumkey.protocol.message import Operation

    good = SignRequest(Operation.LOGIN, RP_ID, "tx", b"\x01" * 32)
    assert token.sign("c1", good)
    with pytest.raises(SigningRefused, match="relying party"):
        token.sign("c1", SignRequest(Operation.LOGIN, "evil.example", "tx", b"\x01" * 32))
    with pytest.raises(SigningRefused, match="not allowed"):
        token.sign("c1", SignRequest(Operation.REGISTER, RP_ID, "tx", b"\x01" * 32))


def test_token_survives_garbage_frames():
    stream = io.BytesIO((10).to_bytes(4, "big") + b"not json!!!")
    out = io.BytesIO()
    token_module.serve(stream, out)
    assert b'"ok":false' in out.getvalue()
    oversized = io.BytesIO((10**9).to_bytes(4, "big"))
    out = io.BytesIO()
    token_module.serve(oversized, out)
    assert b"frame too large" in out.getvalue()
