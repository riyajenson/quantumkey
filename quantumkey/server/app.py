"""FastAPI surface for the QuantumKey relying party.

Routes are a thin wrapper over RelyingParty. Binary values travel as
base64url without padding; non-canonical encodings are rejected.
"""

from __future__ import annotations

import os
import time
from typing import Annotated, Callable

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from quantumkey import crypto
from quantumkey.server.limits import RateLimiter, RequestGuard
from quantumkey.server.service import (
    PROTOCOL_VERSION,
    ProtocolError,
    RelyingParty,
    Started,
)


RATE_LIMIT_PER_MINUTE = 60  # POSTs under /auth/ per client IP
MAX_BODY_BYTES = 64 * 1024  # the largest valid request (migrate, ML-DSA-87) is ~20 KB

# Size limits. A base64url ML-DSA-87 signature is 6,170 characters.
Ident = Annotated[str, Field(min_length=1, max_length=64)]
Algorithm = Annotated[str, Field(max_length=16)]
Blob = Annotated[str, Field(max_length=8192)]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterStart(_Body):
    username: Ident
    invite: Ident
    algorithm: Algorithm = crypto.DEFAULT_ALGORITHM


class RegisterComplete(_Body):
    transaction_id: Ident
    credential_id: Ident
    public_key: Blob
    policy: Blob
    signature: Blob
    device_id: Ident | None = None


class LoginStart(_Body):
    username: Ident
    credential_id: Ident | None = None


class Empty(_Body):
    pass


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
    new_device_id: Ident | None = None


class EnrollStart(_Body):
    username: Ident
    credential_id: Ident  # the authorizing credential
    algorithm: Algorithm = crypto.DEFAULT_ALGORITHM


class EnrollComplete(_Body):
    transaction_id: Ident
    new_credential_id: Ident
    new_public_key: Blob
    new_policy: Blob
    authorizer_signature: Blob
    new_signature: Blob
    new_device_id: Ident | None = None


class RevokeStart(_Body):
    username: Ident
    credential_id: Ident  # the authorizing credential


class RevokeComplete(_Body):
    transaction_id: Ident
    target_credential_id: Ident
    signature: Blob


def _bearer(authorization: str | None) -> str:
    """The token from `Authorization: Bearer <token>`; anything else is treated
    like an unknown token."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token or len(token) > 128:
        raise ProtocolError("invalid_session", 401)
    return token


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
    create_schema: bool = True,
    rate_limit: int | None = RATE_LIMIT_PER_MINUTE,
    max_body: int = MAX_BODY_BYTES,
) -> FastAPI:
    url = database_url or os.environ.get("QK_DATABASE_URL", "sqlite:///quantumkey.sqlite3")
    rp = RelyingParty(
        url, rp_id=rp_id, clock=clock, challenge_ttl=challenge_ttl, create_schema=create_schema
    )
    app = FastAPI(title="QuantumKey relying party (research prototype)")
    app.state.rp = rp
    limiter = RateLimiter(rate_limit, 60.0, clock) if rate_limit is not None else None
    app.add_middleware(RequestGuard, limiter=limiter, max_body=max_body)

    @app.exception_handler(ProtocolError)
    async def protocol_error(_: Request, exc: ProtocolError) -> JSONResponse:
        return JSONResponse(status_code=exc.status, content={"error": exc.code})

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "protocol_version": PROTOCOL_VERSION}

    @app.post("/auth/register/start")
    def register_start(body: RegisterStart) -> dict:
        return _started(rp, "register", rp.register_start(body.username, body.invite, body.algorithm))

    @app.post("/auth/register/complete", status_code=201)
    def register_complete(body: RegisterComplete) -> dict:
        rp.register_complete(
            body.transaction_id,
            body.credential_id,
            _decode(body.public_key),
            _decode(body.policy),
            _decode(body.signature),
            body.device_id,
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

    @app.get("/auth/session")
    def session_info(authorization: Annotated[str | None, Header()] = None) -> dict:
        username, credential_id, expires_at = rp.session_info(_bearer(authorization))
        return {"username": username, "credential_id": credential_id, "expires_at": expires_at}

    @app.post("/auth/logout")
    def logout(_: Empty, authorization: Annotated[str | None, Header()] = None) -> dict:
        rp.logout(_bearer(authorization))
        return {"status": "logged_out"}

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
            body.new_device_id,
        )
        return {"credential_id": new_id, "status": "active"}

    @app.post("/auth/enroll/start")
    def enroll_start(body: EnrollStart) -> dict:
        return _started(
            rp, "enroll", rp.enroll_start(body.username, body.credential_id, body.algorithm)
        )

    @app.post("/auth/enroll/complete")
    def enroll_complete(body: EnrollComplete) -> dict:
        new_id = rp.enroll_complete(
            body.transaction_id,
            body.new_credential_id,
            _decode(body.new_public_key),
            _decode(body.new_policy),
            _decode(body.authorizer_signature),
            _decode(body.new_signature),
            body.new_device_id,
        )
        return {"credential_id": new_id, "status": "active"}

    @app.post("/auth/revoke/start")
    def revoke_start(body: RevokeStart) -> dict:
        return _started(rp, "revoke", rp.revoke_start(body.username, body.credential_id))

    @app.post("/auth/revoke/complete")
    def revoke_complete(body: RevokeComplete) -> dict:
        target = rp.revoke_complete(
            body.transaction_id, body.target_credential_id, _decode(body.signature)
        )
        return {"credential_id": target, "status": "revoked"}

    @app.get("/credentials/{credential_id}")
    def credential_status(credential_id: str) -> dict:
        status, replaced_by, device_id = rp.credential_status(credential_id)
        return {
            "credential_id": credential_id,
            "status": status,
            "replaced_by": replaced_by,
            "device_id": device_id,
        }

    return app
