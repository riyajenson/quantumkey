"""ADR 0009 end to end: enroll a second device, then use it to revoke a lost one."""

import pytest
from fastapi.testclient import TestClient

from quantumkey.authenticator.client import AuthClient, ServerRejected
from quantumkey.authenticator.core import SigningRefused
from quantumkey.authenticator.software import SoftwareSigner
from quantumkey.authenticator.token import VirtualToken
from quantumkey.authenticator.vault import KdfParams
from quantumkey.protocol.policy import Policy
from quantumkey.server.app import create_app
from tests.helpers import RP_ID, database_url, invite

FAST = KdfParams(time_cost=1, memory_kib=8192, parallelism=1)


@pytest.fixture
def http(tmp_path):
    return TestClient(create_app(database_url(tmp_path), rp_id=RP_ID))


@pytest.fixture
def software(tmp_path):
    return SoftwareSigner(tmp_path / "vault.sqlite3", "1234", kdf=FAST)


def test_lost_device_story(http, software):
    client = AuthClient(http, RP_ID)
    laptop = client.register("alice", software, invite=invite(http, "alice"))
    with VirtualToken() as token:
        key = client.enroll("alice", laptop, software, token)
        assert http.get(f"/credentials/{key}").json()["device_id"] == token.device_id
        assert client.login("alice", software, laptop) and client.login("alice", token, key)
        # The laptop is lost: the token revokes it.
        assert client.revoke("alice", key, token, laptop) == laptop
        assert http.get(f"/credentials/{laptop}").json()["status"] == "revoked"
        with pytest.raises(ServerRejected):
            client.login("alice", software, laptop)
        assert client.login("alice", token, key)
        # The token is now the only credential and cannot revoke itself.
        with pytest.raises(ServerRejected) as error:
            client.revoke("alice", key, token, key)
        assert error.value.code == "last_credential"


def test_token_refuses_to_revoke_when_its_policy_does_not_allow_it(http, software):
    client = AuthClient(http, RP_ID)
    laptop = client.register("alice", software, invite=invite(http, "alice"))
    with VirtualToken() as token:
        key = client.enroll(
            "alice", laptop, software, token,
            policy=Policy(rp_id=RP_ID, allowed_ops=("register", "login")),
        )
        with pytest.raises(SigningRefused, match="not allowed"):
            client.revoke("alice", key, token, laptop)
    assert http.get(f"/credentials/{laptop}").json()["status"] == "active"
