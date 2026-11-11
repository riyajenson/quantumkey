"""Relying-party data model. The schema has no private-key field."""

from __future__ import annotations

from sqlalchemy import Float, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)


class Credential(Base):
    __tablename__ = "credentials"

    credential_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    policy: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    policy_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # active | revoked
    replaced_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)


class Challenge(Base):
    __tablename__ = "challenges"

    transaction_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(16), nullable=False)  # register | login | migrate
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    credential_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    challenge: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    used_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)
    invite_id: Mapped[str | None] = mapped_column(String(32), nullable=True)


class EnrollmentInvite(Base):
    """A single-use permission to register one username. Only the token's
    SHA-256 is stored; the token itself is shown once, when issued."""

    __tablename__ = "enrollment_invites"

    invite_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, unique=True)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    used_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[float] = mapped_column(Float, nullable=False)
