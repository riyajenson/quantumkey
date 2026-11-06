"""FastAPI surface for the QuantumKey relying party.

Routes are a thin wrapper over RelyingParty. Binary values travel as
base64url without padding; non-canonical encodings are rejected.
"""

from __future__ import annotations

import os
import time
from typing import Annotated, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from quantumkey import crypto
from quantumkey.server.service import (
    PROTOCOL_VERSION,
    ProtocolError,
    RelyingParty,
    Started,
)


# Size limits. A base64url ML-DSA-87 signature is 6,170 characters.
Ident = Annotated[str, Field(min_length=1, max_length=64)]
Algorithm = Annotated[str, Field(max_length=16)]
Blob = Annotated[str, Field(max_length=8192)]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterStart(_Body):
    username: Ident
    algorithm: Algorithm = crypto.DEFAULT_ALGORITHM


class RegisterComplete(_Body):
    transaction_id: Ident
    credential_id: Ident
    public_key: Blob
    policy: Blob
    signature: Blob


class LoginStart(_Body):
    username: Ident
    credential_id: Ident | None = None


class LoginComplete(_Body):
    transaction_id: Ident
    credential_id: Ident
    signature: Blob


class MigrateStart(_Body):
    username: Ident
    credential_id: Ident
    algorithm: Algorithm = crypto.DEFAULT_ALGORITHM


class MigrateComplete(_Body):
    transaction_id: Ident
    new_credential_id: Ident
    new_public_key: Blob
    new_policy: Blob
    old_signature: Blob
    new_signature: Blob


def _decode(value: str) -> bytes:
    try:
        return crypto.b64d(value)
    except crypto.CryptoError as exc:
        raise ProtocolError("invalid_encoding", 422) from exc


def _started(rp: RelyingParty, operation: str, started: Started) -> dict:
    body = {
        "protocol_version": PROTOCOL_VERSION,
        "operation": operation,
        "rp_id": rp.rp_id,
        "transaction_id": started.transaction_id,
        "challenge": crypto.b64e(started.challenge),
        "expires_at": started.expires_at,
        "algorithm": started.algorithm,
    }
    if started.credential_id is not None:
        body["credential_id"] = started.credential_id
    return body


def create_app(
    database_url: str | None = None,
    rp_id: str = "quantumkey.local",
    clock: Callable[[], float] = time.time,
    challenge_ttl: float = 60.0,
) -> FastAPI:
    url = database_url or os.environ.get("QK_DATABASE_URL", "sqlite:///quantumkey.sqlite3")
    rp = RelyingParty(url, rp_id=rp_id, clock=clock, challenge_ttl=challenge_ttl)
    app = FastAPI(title="QuantumKey relying party (research prototype)")
    app.state.rp = rp

    @app.exception_handler(ProtocolError)
    async def protocol_error(_: Request, exc: ProtocolError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"error": exc.code})

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "protocol_version": PROTOCOL_VERSION}

    @app.post("/auth/register/start")
    def register_start(body: RegisterStart) -> dict:
        return _started(rp, "register", rp.register_start(body.username, body.algorithm))

    @app.post("/auth/register/complete", status_code=201)
    def register_complete(body: RegisterComplete) -> dict:
        rp.register_complete(
            body.transaction_id,
            body.credential_id,
            _decode(body.public_key),
            _decode(body.policy),
            _decode(body.signature),
        )
        return {"credential_id": body.credential_id, "status": "active"}

    @app.post("/auth/login/start")
    def login_start(body: LoginStart) -> dict:
        return _started(rp, "login", rp.login_start(body.username, body.credential_id))

    @app.post("/auth/login/complete")
    def login_complete(body: LoginComplete) -> dict:
        token = rp.login_complete(
            body.transaction_id, body.credential_id, _decode(body.signature)
        )
        return {"authenticated": True, "session_token": token}

    @app.post("/auth/migrate/start")
    def migrate_start(body: MigrateStart) -> dict:
        return _started(
            rp, "migrate", rp.migrate_start(body.username, body.credential_id, body.algorithm)
        )

    @app.post("/auth/migrate/complete")
    def migrate_complete(body: MigrateComplete) -> dict:
        new_id = rp.migrate_complete(
            body.transaction_id,
            body.new_credential_id,
            _decode(body.new_public_key),
            _decode(body.new_policy),
            _decode(body.old_signature),
            _decode(body.new_signature),
        )
        return {"credential_id": new_id, "status": "active"}

    @app.get("/credentials/{credential_id}")
    def credential_status(credential_id: str) -> dict:
        status, replaced_by = rp.credential_status(credential_id)
        return {"credential_id": credential_id, "status": status, "replaced_by": replaced_by}

    return app
