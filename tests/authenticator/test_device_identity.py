"""Phase 5: device identity. Each vault and each virtual token has a random,
stable device id; the server records which device a credential was created on.
The id is self-reported by the client: it identifies, it does not attest."""

import re

import pytest
from fastapi.testclient import TestClient

from quantumkey.authenticator.client import AuthClient
from quantumkey.authenticator.software import SoftwareSigner
from quantumkey.authenticator.token import VirtualToken, handle
from quantumkey.authenticator.core import SigningCore
from quantumkey.authenticator.vault import KdfParams, Vault
from quantumkey.server.app import create_app
from tests.helpers import RP_ID, database_url, invite, start_registration

FAST = KdfParams(time_cost=1, memory_kib=8192, parallelism=1)
DEVICE_ID = re.compile(r"^qkd-[0-9a-f]{32}$")


@pytest.fixture
def http(tmp_path):
    return TestClient(create_app(database_url(tmp_path), rp_id=RP_ID))


def test_vault_device_id_is_random_and_stable(tmp_path):
    first = Vault(tmp_path / "a.sqlite3", kdf=FAST)
    assert DEVICE_ID.match(first.device_id)
    assert Vault(tmp_path / "a.sqlite3").device_id == first.device_id
    assert Vault(tmp_path / "b.sqlite3", kdf=FAST).device_id != first.device_id


def test_software_signer_reports_its_vault_device_id(tmp_path):
    signer = SoftwareSigner(tmp_path / "v.sqlite3", "1234", kdf=FAST)
    assert signer.device_id == signer.vault.device_id


def test_token_info_command_reports_a_device_id_and_nothing_else():
    reply = handle(SigningCore(), {"cmd": "info"}, device_id="qkd-" + "0" * 32)
    assert reply == {"ok": True, "device_id": "qkd-" + "0" * 32}
    assert handle(SigningCore(), {"cmd": "info", "x": 1}, device_id="d")["ok"] is False


def test_each_virtual_token_has_its_own_stable_device_id():
    with VirtualToken() as first, VirtualToken() as second:
        assert DEVICE_ID.match(first.device_id)
        assert first.device_id == first.device_id
        assert first.device_id != second.device_id


def test_server_records_the_device_a_credential_was_registered_on(http, tmp_path):
    signer = SoftwareSigner(tmp_path / "v.sqlite3", "1234", kdf=FAST)
    credential_id = AuthClient(http, RP_ID).register("alice", signer, invite=invite(http, "alice"))
    status = http.get(f"/credentials/{credential_id}").json()
    assert status["device_id"] == signer.device_id


def test_migration_records_the_new_device(http, tmp_path):
    signer = SoftwareSigner(tmp_path / "v.sqlite3", "1234", kdf=FAST)
    client = AuthClient(http, RP_ID)
    old_id = client.register("alice", signer, invite=invite(http, "alice"))
    with VirtualToken() as token:
        new_id = client.migrate("alice", old_id, signer, token)
        assert http.get(f"/credentials/{new_id}").json()["device_id"] == token.device_id
    assert http.get(f"/credentials/{old_id}").json()["device_id"] == signer.device_id


def test_device_id_is_optional_for_older_clients(http):
    from tests.helpers import register

    cred = register(http, "alice")  # the test helper sends no device_id
    assert http.get(f"/credentials/{cred.credential_id}").json()["device_id"] is None


def test_overlong_device_id_is_rejected(http):
    started = start_registration(http, "alice").json()
    response = http.post(
        "/auth/register/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": "c",
            "public_key": "AA",
            "policy": "AA",
            "signature": "AA",
            "device_id": "x" * 65,
        },
    )
    assert response.status_code == 422
