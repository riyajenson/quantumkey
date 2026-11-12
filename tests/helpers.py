"""Minimal protocol client used by server tests (not the real authenticator)."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from quantumkey import crypto
from quantumkey.protocol.message import Operation, SignedMessage
from quantumkey.protocol.policy import Policy
from quantumkey.protocol.migration import migration_binding

RP_ID = "quantumkey.local"


def database_url(tmp_path) -> str:
    """Per-test SQLite file, or the opt-in PostgreSQL test database (emptied first).

    PostgreSQL is only accepted on loopback with a database named qk_test_*, so a
    stray QK_TEST_DATABASE_URL can never point the suite at real data.
    """
    import os

    from sqlalchemy.engine import make_url

    configured = os.environ.get("QK_TEST_DATABASE_URL")
    if not configured:
        return "sqlite:///" + (tmp_path / "rp.sqlite3").as_posix()
    url = make_url(configured)
    if url.host not in ("127.0.0.1", "localhost", "::1") or not (url.database or "").startswith("qk_test_"):
        raise RuntimeError("QK_TEST_DATABASE_URL must be loopback with a qk_test_* database")
    from sqlalchemy import create_engine, text

    engine = create_engine(configured)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
    engine.dispose()
    return configured


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@dataclass
class Cred:
    credential_id: str
    algorithm: str
    public_key: bytes
    private_key: bytes
    policy: Policy


def new_cred(algorithm: str = "ML-DSA-65", policy: Policy | None = None) -> Cred:
    public_key, private_key = crypto.generate_keypair(algorithm)
    return Cred(
        credential_id="cred-" + secrets.token_hex(6),
        algorithm=algorithm,
        public_key=public_key,
        private_key=private_key,
        policy=policy or Policy(rp_id=RP_ID),
    )


def message(
    operation: Operation,
    started: dict,
    cred: Cred,
    extra: bytes = b"",
    rp_id: str = RP_ID,
) -> bytes:
    return SignedMessage(
        operation=operation,
        rp_id=rp_id.encode(),
        transaction_id=started["transaction_id"].encode(),
        challenge=crypto.b64d(started["challenge"]),
        credential_id=cred.credential_id.encode(),
        algorithm=cred.algorithm.encode(),
        policy_hash=cred.policy.digest(),
        extra=extra,
    ).encode()


def invite(http, username: str) -> str:
    """Issue an enrollment invite through the app's relying party (operator action)."""
    return http.app.state.rp.issue_invite(username)


def start_registration(client, username: str, algorithm: str = "ML-DSA-65"):
    """Issue an invite for `username` and post register/start with it."""
    invite = client.app.state.rp.issue_invite(username)
    return client.post(
        "/auth/register/start",
        json={"username": username, "invite": invite, "algorithm": algorithm},
    )


def register(client, username: str, cred: Cred | None = None) -> Cred:
    cred = cred or new_cred()
    started = start_registration(client, username, cred.algorithm).json()
    signature = crypto.sign(
        cred.algorithm,
        cred.private_key,
        message(
            Operation.REGISTER, started, cred, extra=hashlib.sha256(cred.public_key).digest()
        ),
    )
    response = client.post(
        "/auth/register/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": cred.credential_id,
            "public_key": crypto.b64e(cred.public_key),
            "policy": crypto.b64e(cred.policy.canonical_bytes()),
            "signature": crypto.b64e(signature),
        },
    )
    assert response.status_code == 201, response.text
    return cred


def login_signature(started: dict, cred: Cred) -> bytes:
    return crypto.sign(
        cred.algorithm, cred.private_key, message(Operation.LOGIN, started, cred)
    )


def login_body(started: dict, cred: Cred, signature: bytes) -> dict:
    return {
        "transaction_id": started["transaction_id"],
        "credential_id": cred.credential_id,
        "signature": crypto.b64e(signature),
    }


def migration_signatures(
    started: dict, old: Cred, new: Cred, operation: Operation = Operation.MIGRATE
) -> tuple[bytes, bytes]:
    """The authorizer's signature over the new-credential binding (migrate or
    enroll) and the new key's proof of possession."""
    binding = migration_binding(
        new.credential_id, new.algorithm, new.public_key, new.policy.digest()
    )
    old_sig = crypto.sign(
        old.algorithm, old.private_key, message(operation, started, old, extra=binding)
    )
    new_sig = crypto.sign(
        new.algorithm,
        new.private_key,
        message(
            Operation.REGISTER, started, new, extra=hashlib.sha256(new.public_key).digest()
        ),
    )
    return old_sig, new_sig


def migrate_body(started: dict, new: Cred, old_sig: bytes, new_sig: bytes) -> dict:
    return {
        "transaction_id": started["transaction_id"],
        "new_credential_id": new.credential_id,
        "new_public_key": crypto.b64e(new.public_key),
        "new_policy": crypto.b64e(new.policy.canonical_bytes()),
        "old_signature": crypto.b64e(old_sig),
        "new_signature": crypto.b64e(new_sig),
    }
