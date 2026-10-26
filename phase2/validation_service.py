"""Temporary FastAPI/SQLAlchemy service used only by Phase 2 E2E experiments."""

from __future__ import annotations

import base64
import binascii
import os
from contextlib import asynccontextmanager
from pathlib import Path

import oqs
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import LargeBinary, String, create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


def _database_url() -> str:
    path = Path(os.environ.get("QK_VALIDATION_DATABASE", "phase2-validation.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path.as_posix()}"


engine = create_engine(
    _database_url(), connect_args={"check_same_thread": False}
)


class Base(DeclarativeBase):
    pass


class Credential(Base):
    __tablename__ = "credentials"

    credential_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class CredentialRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    credential_id: str
    algorithm: str
    public_key: str


class VerifyRequest(BaseModel):
    credential_id: str
    message: str
    signature: str


def _decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"invalid {field} encoding") from exc


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(engine)
    yield


app = FastAPI(title="QuantumKey Phase 2 validation only", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/credentials", status_code=status.HTTP_201_CREATED)
def register_credential(body: CredentialRequest) -> dict[str, str]:
    if len(body.credential_id) > 128:
        raise HTTPException(status_code=422, detail="credential_id is too long")
    if body.algorithm not in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        raise HTTPException(status_code=422, detail="unsupported algorithm")
    public_key = _decode(body.public_key, "public_key")
    try:
        with Session(engine) as session, session.begin():
            session.add(
                Credential(
                    credential_id=body.credential_id,
                    algorithm=body.algorithm,
                    public_key=public_key,
                )
            )
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="credential already exists") from exc
    return {"credential_id": body.credential_id}


@app.get("/credentials/{credential_id}")
def get_credential(credential_id: str) -> dict[str, str]:
    with Session(engine) as session:
        credential = session.get(Credential, credential_id)
        if credential is None:
            raise HTTPException(status_code=404, detail="credential not found")
        return {
            "credential_id": credential.credential_id,
            "algorithm": credential.algorithm,
            "public_key": base64.b64encode(credential.public_key).decode("ascii"),
        }


@app.post("/verify")
def verify_signature(body: VerifyRequest) -> dict[str, bool]:
    with Session(engine) as session:
        credential = session.get(Credential, body.credential_id)
        if credential is None:
            raise HTTPException(status_code=404, detail="credential not found")
        message = _decode(body.message, "message")
        signature = _decode(body.signature, "signature")
        try:
            with oqs.Signature(credential.algorithm) as verifier:
                valid = verifier.verify(message, signature, credential.public_key)
        except (ValueError, RuntimeError):
            valid = False
        return {"valid": bool(valid)}
