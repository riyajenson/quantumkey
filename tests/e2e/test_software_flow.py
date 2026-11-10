"""Phase 4 milestone: keygen + challenge + signing + verification, end to end,
with the negative cases the gate requires."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from quantumkey import crypto
from quantumkey.authenticator.client import AuthClient, ServerRejected
from quantumkey.authenticator.core import SignRequest, SigningRefused
from quantumkey.authenticator.software import SoftwareSigner
from quantumkey.authenticator.vault import Vault, VaultUnlockError
from quantumkey.protocol.message import Operation
from quantumkey.protocol.policy import Policy
from quantumkey.server.app import create_app
from tests.helpers import RP_ID, FakeClock, invite


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def http(tmp_path, clock):
    app = create_app("sqlite:///" + (tmp_path / "rp.sqlite3").as_posix(), rp_id=RP_ID, clock=clock)
    return TestClient(app)


@pytest.fixture
def signer(tmp_path, clock):
    return SoftwareSigner(tmp_path / "vault.sqlite3", pin="1234", clock=clock)


@pytest.mark.parametrize("algorithm", crypto.ALGORITHMS)
def test_register_and_login_for_every_variant(http, signer, algorithm):
    client = AuthClient(http, RP_ID)
    credential_id = client.register("alice", signer, algorithm=algorithm, invite=invite(http, "alice"))
    for _ in range(2):
        assert client.login("alice", signer, credential_id)


def test_multiple_credentials_in_one_vault(http, signer):
    client = AuthClient(http, RP_ID)
    first = client.register("alice", signer, invite=invite(http, "alice"))
    second = client.register("bob", signer, algorithm="ML-DSA-44", invite=invite(http, "bob"))
    assert {c.credential_id for c in signer.vault.list_credentials()} == {first, second}
    assert client.login("bob", signer, second)


def test_wrong_pin_cannot_sign_and_data_stays_private(http, tmp_path, clock):
    path = tmp_path / "vault.sqlite3"
    client = AuthClient(http, RP_ID)
    credential_id = client.register("alice", SoftwareSigner(path, "1234", clock), invite=invite(http, "alice"))
    with pytest.raises(VaultUnlockError):
        client.login("alice", SoftwareSigner(path, "0000", clock), credential_id)
    # The private key does not appear in the vault file in plaintext.
    private_key = Vault(path).unlock("1234", credential_id)
    assert private_key not in path.read_bytes()


def test_tampered_vault_policy_is_detected(http, tmp_path, clock):
    path = tmp_path / "vault.sqlite3"
    client = AuthClient(http, RP_ID)
    signer = SoftwareSigner(path, "1234", clock)
    credential_id = client.register("alice", signer, invite=invite(http, "alice"))
    weaker = Policy(rp_id=RP_ID, max_signs_per_minute=1000)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE credentials SET policy = ?", (weaker.canonical_bytes(),))
    with pytest.raises(VaultUnlockError):
        signer.sign(
            credential_id,
            SignRequest(Operation.LOGIN, RP_ID, "tx", b"\x00" * 32),
        )


def test_signer_refuses_other_relying_parties_and_disallowed_operations(http, signer):
    client = AuthClient(http, RP_ID)
    credential_id = client.register(
        "alice", signer, policy=Policy(rp_id=RP_ID, allowed_ops=("register", "login")),
        invite=invite(http, "alice"),
    )
    challenge = b"\x07" * 32
    with pytest.raises(SigningRefused):
        signer.sign(credential_id, SignRequest(Operation.LOGIN, "evil.example", "tx", challenge))
    with pytest.raises(SigningRefused):
        # Migration was not granted by this credential's policy.
        from quantumkey.authenticator.core import MigrationTarget

        target = MigrationTarget("x", "ML-DSA-65", b"k", b"h" * 32)
        signer.sign(credential_id, SignRequest(Operation.MIGRATE, RP_ID, "tx", challenge, target))


def test_signer_enforces_rate_limit_and_expiry(http, tmp_path, clock):
    signer = SoftwareSigner(tmp_path / "vault.sqlite3", "1234", clock)
    client = AuthClient(http, RP_ID)
    credential_id = client.register(
        "alice", signer, policy=Policy(rp_id=RP_ID, max_signs_per_minute=3, not_after=int(clock.now) + 300),
        invite=invite(http, "alice"),
    )  # registration used 1 signature
    request = SignRequest(Operation.LOGIN, RP_ID, "tx", b"\x01" * 32)
    signer.sign(credential_id, request)
    signer.sign(credential_id, request)
    with pytest.raises(SigningRefused, match="rate limit"):
        signer.sign(credential_id, request)
    clock.now += 61
    signer.sign(credential_id, request)  # window has passed
    clock.now += 400
    with pytest.raises(SigningRefused, match="expired"):
        signer.sign(credential_id, request)


def test_signer_rejects_malformed_requests(signer):
    signer.create_credential("ML-DSA-65", Policy(rp_id=RP_ID), "c1")
    with pytest.raises(SigningRefused):
        signer.sign("c1", SignRequest(Operation.LOGIN, RP_ID, "tx", b"short"))
    with pytest.raises(SigningRefused):
        signer.sign("missing", SignRequest(Operation.LOGIN, RP_ID, "tx", b"\x00" * 32))
    with pytest.raises(SigningRefused):  # migrate without a target
        signer.sign("c1", SignRequest(Operation.MIGRATE, RP_ID, "tx", b"\x00" * 32))


def test_signature_for_one_operation_is_useless_for_another(http, signer):
    """A login signature cannot be replayed as a migration authorization."""
    client = AuthClient(http, RP_ID)
    old_id = client.register("alice", signer, invite=invite(http, "alice"))
    started = http.post(
        "/auth/migrate/start", json={"username": "alice", "credential_id": old_id}
    ).json()
    challenge = crypto.b64d(started["challenge"])
    tx = started["transaction_id"]
    attacker = signer.create_credential("ML-DSA-65", Policy(rp_id=RP_ID), "qk-attacker")
    # The attacker only holds a LOGIN signature from the old credential.
    wrong_old_sig = signer.sign(old_id, SignRequest(Operation.LOGIN, RP_ID, tx, challenge))
    new_sig = signer.sign("qk-attacker", SignRequest(Operation.REGISTER, RP_ID, tx, challenge))
    response = http.post(
        "/auth/migrate/complete",
        json={
            "transaction_id": tx,
            "new_credential_id": "qk-attacker",
            "new_public_key": crypto.b64e(attacker.public_key),
            "new_policy": crypto.b64e(Policy(rp_id=RP_ID).canonical_bytes()),
            "old_signature": crypto.b64e(wrong_old_sig),
            "new_signature": crypto.b64e(new_sig),
        },
    )
    assert response.status_code == 401
    assert http.get(f"/credentials/{old_id}").json()["status"] == "active"
    with pytest.raises(ServerRejected):
        AuthClient(http, RP_ID).login("alice", signer, "qk-attacker")
