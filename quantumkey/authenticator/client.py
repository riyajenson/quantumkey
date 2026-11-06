"""Protocol client: drives register / login / migrate against the server using
any Signer. `http` is anything with httpx-style .post(path, json=...), so
tests can inject a Starlette TestClient and the CLI can inject httpx.Client."""

from __future__ import annotations

import secrets
from typing import Any

from quantumkey import crypto
from quantumkey.authenticator.core import MigrationTarget, SignRequest, Signer
from quantumkey.protocol.message import Operation
from quantumkey.protocol.policy import Policy


class ServerRejected(Exception):
    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"{status}: {code}")
        self.status = status
        self.code = code


def new_credential_id() -> str:
    return "qk-" + secrets.token_hex(8)


class AuthClient:
    def __init__(self, http: Any, rp_id: str) -> None:
        self.http = http
        self.rp_id = rp_id

    def _post(self, path: str, body: dict) -> dict:
        response = self.http.post(path, json=body)
        data = response.json()
        if response.status_code >= 400:
            raise ServerRejected(response.status_code, data.get("error", "unknown"))
        return data

    def _request(self, operation: Operation, started: dict, target=None) -> SignRequest:
        return SignRequest(
            operation=operation,
            rp_id=started["rp_id"],
            transaction_id=started["transaction_id"],
            challenge=crypto.b64d(started["challenge"]),
            target=target,
        )

    def register(
        self,
        username: str,
        signer: Signer,
        algorithm: str = crypto.DEFAULT_ALGORITHM,
        policy: Policy | None = None,
    ) -> str:
        policy = policy or Policy(rp_id=self.rp_id)
        started = self._post(
            "/auth/register/start", {"username": username, "algorithm": algorithm}
        )
        credential_id = new_credential_id()
        public = signer.create_credential(started["algorithm"], policy, credential_id)
        signature = signer.sign(credential_id, self._request(Operation.REGISTER, started))
        self._post(
            "/auth/register/complete",
            {
                "transaction_id": started["transaction_id"],
                "credential_id": credential_id,
                "public_key": crypto.b64e(public.public_key),
                "policy": crypto.b64e(policy.canonical_bytes()),
                "signature": crypto.b64e(signature),
            },
        )
        return credential_id

    def login(self, username: str, signer: Signer, credential_id: str | None = None) -> str:
        started = self._post(
            "/auth/login/start",
            {"username": username, **({"credential_id": credential_id} if credential_id else {})},
        )
        credential_id = started["credential_id"]
        signature = signer.sign(credential_id, self._request(Operation.LOGIN, started))
        result = self._post(
            "/auth/login/complete",
            {
                "transaction_id": started["transaction_id"],
                "credential_id": credential_id,
                "signature": crypto.b64e(signature),
            },
        )
        return result["session_token"]

    def migrate(
        self,
        username: str,
        old_credential_id: str,
        old_signer: Signer,
        new_signer: Signer,
        algorithm: str = crypto.DEFAULT_ALGORITHM,
        policy: Policy | None = None,
    ) -> str:
        """Create a fresh credential in `new_signer`, authorized by the old one.
        No private key is exported from either signer."""
        policy = policy or Policy(rp_id=self.rp_id)
        started = self._post(
            "/auth/migrate/start",
            {"username": username, "credential_id": old_credential_id, "algorithm": algorithm},
        )
        new_id = new_credential_id()
        new_public = new_signer.create_credential(started["algorithm"], policy, new_id)
        target = MigrationTarget(
            new_id, new_public.algorithm, new_public.public_key, policy.digest()
        )
        old_signature = old_signer.sign(
            old_credential_id, self._request(Operation.MIGRATE, started, target)
        )
        new_signature = new_signer.sign(new_id, self._request(Operation.REGISTER, started))
        self._post(
            "/auth/migrate/complete",
            {
                "transaction_id": started["transaction_id"],
                "new_credential_id": new_id,
                "new_public_key": crypto.b64e(new_public.public_key),
                "new_policy": crypto.b64e(policy.canonical_bytes()),
                "old_signature": crypto.b64e(old_signature),
                "new_signature": crypto.b64e(new_signature),
            },
        )
        return new_id
