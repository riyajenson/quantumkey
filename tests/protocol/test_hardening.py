"""Type-confusion and input-size hardening."""

import sqlite3

import pytest
from fastapi.testclient import TestClient

from quantumkey import crypto
from quantumkey.authenticator.core import SigningCore
from quantumkey.authenticator.token import handle
from quantumkey.authenticator.vault import Vault, VaultError, _aad
from quantumkey.protocol.policy import Policy, PolicyError
from quantumkey.server.app import create_app

RP = "quantumkey.local"


@pytest.mark.parametrize(
    "document",
    [
        b'{"allowed_ops":["login"],"max_signs_per_minute":1,"not_after":true,"rp_id":"quantumkey.local"}',
        b'{"allowed_ops":["login"],"max_signs_per_minute":1.5,"not_after":null,"rp_id":"quantumkey.local"}',
        b'{"allowed_ops":["login"],"max_signs_per_minute":true,"not_after":null,"rp_id":"quantumkey.local"}',
        b'{"allowed_ops":["login"],"max_signs_per_minute":1,"not_after":null,"rp_id":5}',
        b'{"allowed_ops":"login","max_signs_per_minute":1,"not_after":null,"rp_id":"quantumkey.local"}',
        b'{"allowed_ops":[1],"max_signs_per_minute":1,"not_after":null,"rp_id":"quantumkey.local"}',
    ],
)
def test_policy_rejects_wrong_types(document):
    with pytest.raises(PolicyError):
        Policy.from_bytes(document)


def test_vault_aad_is_unambiguous():
    # A NUL inside one field must not be confusable with the field separator.
    assert _aad("a\x00b", "c", b"h") != _aad("a", "b\x00c", b"h")


def test_vault_rejects_duplicate_credential(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3")
    policy = Policy(rp_id=RP)
    vault.put("1234", "c1", "ML-DSA-44", b"pk", policy, b"sk")
    with pytest.raises(VaultError):
        vault.put("1234", "c1", "ML-DSA-44", b"pk", policy, b"sk")


def test_vault_rejects_unknown_format_version(tmp_path):
    path = tmp_path / "v.sqlite3"
    vault = Vault(path)
    vault.put("1234", "c1", "ML-DSA-44", b"pk", Policy(rp_id=RP), b"sk")
    with sqlite3.connect(path) as db:
        db.execute("UPDATE credentials SET format_version = 99")
    with pytest.raises(VaultError):
        vault.unlock("1234", "c1")


@pytest.mark.parametrize(
    "overrides",
    [
        {"operation": True},
        {"operation": "2"},
        {"rp_id": 7},
        {"transaction_id": ["tx"]},
        {"credential_id": 1},
        {"challenge": 123},
    ],
)
def test_token_rejects_wrong_types(overrides):
    core = SigningCore()
    core.create("ML-DSA-44", Policy(rp_id=RP), "c1")
    message = {
        "cmd": "sign",
        "credential_id": "c1",
        "operation": 2,
        "rp_id": RP,
        "transaction_id": "tx",
        "challenge": crypto.b64e(b"\x00" * 32),
        "target": None,
    }
    message.update(overrides)
    assert handle(core, message) == {"ok": False, "error": "malformed request"}


def test_api_rejects_oversized_fields(tmp_path):
    client = TestClient(create_app("sqlite:///" + (tmp_path / "rp.sqlite3").as_posix(), rp_id=RP))
    huge = "A" * 20_000
    response = client.post(
        "/auth/login/complete",
        json={"transaction_id": huge, "credential_id": "c", "signature": "AA"},
    )
    assert response.status_code == 422
