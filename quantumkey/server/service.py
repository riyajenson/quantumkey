"""Relying-party logic: challenge lifecycle, registration, login, migration.

The server reconstructs the canonical signed message from its own records and
never accepts a client-supplied message. A challenge is consumed by one atomic
conditional UPDATE before any signature is checked, so each challenge allows
exactly one attempt even under concurrent requests.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from sqlalchemy import create_engine, delete, or_, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from quantumkey import crypto
from quantumkey.protocol.message import Operation, SignedMessage
from quantumkey.protocol.migration import migration_binding
from quantumkey.protocol.policy import Policy, PolicyError
from quantumkey.server.models import Base, Challenge, Credential, EnrollmentInvite, User

PROTOCOL_VERSION = 1
MAX_ID_LENGTH = 64
INVITE_TTL = 24 * 60 * 60  # seconds
PURGE_INTERVAL = 60.0  # seconds between automatic purges


class ProtocolError(Exception):
    """A protocol failure with a stable code and HTTP status."""

    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class Started:
    transaction_id: str
    challenge: bytes
    expires_at: float
    algorithm: str
    credential_id: str | None = None


class RelyingParty:
    def __init__(
        self,
        database_url: str,
        rp_id: str,
        clock: Callable[[], float] = time.time,
        challenge_ttl: float = 60.0,
        create_schema: bool = True,
    ) -> None:
        self.rp_id = rp_id
        self.clock = clock
        self.challenge_ttl = challenge_ttl
        self._last_purge = float("-inf")
        kwargs = {"connect_args": {"check_same_thread": False}} if database_url.startswith("sqlite") else {}
        self.engine: Engine = create_engine(database_url, **kwargs)
        if create_schema:  # production deployments run `alembic upgrade head` instead
            Base.metadata.create_all(self.engine)

    # -- challenge lifecycle -------------------------------------------------

    def _issue(
        self,
        purpose: str,
        username: str,
        algorithm: str,
        credential_id: str | None = None,
        invite_id: str | None = None,
    ) -> Started:
        now = self.clock()
        if now - self._last_purge >= PURGE_INTERVAL:
            self.purge_expired()
        started = Started(
            transaction_id=secrets.token_urlsafe(24),
            challenge=secrets.token_bytes(32),
            expires_at=now + self.challenge_ttl,
            algorithm=algorithm,
            credential_id=credential_id,
        )
        with Session(self.engine) as session, session.begin():
            session.add(
                Challenge(
                    transaction_id=started.transaction_id,
                    purpose=purpose,
                    username=username,
                    credential_id=credential_id,
                    algorithm=algorithm,
                    challenge=started.challenge,
                    expires_at=started.expires_at,
                    created_at=now,
                    invite_id=invite_id,
                )
            )
        return started

    def purge_expired(self) -> tuple[int, int]:
        """Delete expired challenges and expired or spent invites; return how many
        of each. Such rows can never be used again, so this changes no behavior.
        Runs automatically from _issue at most once per PURGE_INTERVAL."""
        now = self.clock()
        self._last_purge = now
        with Session(self.engine) as session, session.begin():
            challenges = session.execute(
                delete(Challenge).where(Challenge.expires_at <= now)
            ).rowcount
            invites = session.execute(
                delete(EnrollmentInvite).where(
                    or_(EnrollmentInvite.expires_at <= now, EnrollmentInvite.used_at.is_not(None))
                )
            ).rowcount
        return challenges, invites

    def _consume(self, transaction_id: str, purpose: str) -> Challenge:
        """Atomically mark the challenge used. Unknown, expired, reused, or
        wrong-purpose challenges all fail identically."""
        now = self.clock()
        with Session(self.engine) as session, session.begin():
            result = session.execute(
                update(Challenge)
                .where(
                    Challenge.transaction_id == transaction_id,
                    Challenge.purpose == purpose,
                    Challenge.used_at.is_(None),
                    Challenge.expires_at > now,
                )
                .values(used_at=now)
            )
            if result.rowcount != 1:
                raise ProtocolError("invalid_challenge", 400)
            row = session.get(Challenge, transaction_id)
            session.expunge(row)
            return row

    def _message(
        self,
        operation: Operation,
        challenge: Challenge,
        credential_id: str,
        algorithm: str,
        policy_hash: bytes,
        extra: bytes = b"",
    ) -> bytes:
        return SignedMessage(
            operation=operation,
            rp_id=self.rp_id.encode(),
            transaction_id=challenge.transaction_id.encode(),
            challenge=challenge.challenge,
            credential_id=credential_id.encode(),
            algorithm=algorithm.encode(),
            policy_hash=policy_hash,
            extra=extra,
        ).encode()

    def _parse_policy(self, policy_bytes: bytes) -> Policy:
        try:
            policy = Policy.from_bytes(policy_bytes)
        except PolicyError as exc:
            raise ProtocolError("invalid_policy", 422) from exc
        if policy.rp_id != self.rp_id:
            raise ProtocolError("invalid_policy", 422)
        return policy

    @staticmethod
    def _check_ids(*values: str) -> None:
        for value in values:
            if not value or len(value) > MAX_ID_LENGTH or not value.isprintable():
                raise ProtocolError("invalid_identifier", 422)

    @staticmethod
    def _check_key(algorithm: str, public_key: bytes) -> None:
        try:
            crypto.require_algorithm(algorithm)
        except crypto.CryptoError as exc:
            raise ProtocolError("unsupported_algorithm", 422) from exc
        if len(public_key) != crypto.SIZES[algorithm][0]:
            raise ProtocolError("invalid_public_key", 422)

    # -- enrollment invites ----------------------------------------------------

    def issue_invite(self, username: str, ttl: float = INVITE_TTL) -> str:
        """Create a single-use invite for `username` and return its token.
        The token is not stored and cannot be shown again."""
        self._check_ids(username)
        token = secrets.token_urlsafe(32)
        now = self.clock()
        with Session(self.engine) as session, session.begin():
            if session.get(User, username) is not None:
                raise ProtocolError("user_exists", 409)
            session.add(
                EnrollmentInvite(
                    invite_id=secrets.token_hex(8),
                    username=username,
                    token_hash=hashlib.sha256(token.encode()).digest(),
                    expires_at=now + ttl,
                    created_at=now,
                )
            )
        return token

    # -- registration ----------------------------------------------------------

    def register_start(
        self, username: str, invite: str, algorithm: str = crypto.DEFAULT_ALGORITHM
    ) -> Started:
        self._check_ids(username)
        if algorithm not in crypto.ALGORITHMS:
            raise ProtocolError("unsupported_algorithm", 422)
        with Session(self.engine) as session:
            # The invite is checked before the username, so only an invite holder
            # can learn whether a name is taken.
            row = session.scalars(
                select(EnrollmentInvite).where(
                    EnrollmentInvite.token_hash == hashlib.sha256(invite.encode()).digest(),
                    EnrollmentInvite.username == username,
                    EnrollmentInvite.used_at.is_(None),
                    EnrollmentInvite.expires_at > self.clock(),
                )
            ).first()
            if row is None:
                raise ProtocolError("invalid_invite", 403)
            if session.get(User, username) is not None:
                raise ProtocolError("user_exists", 409)
            invite_id = row.invite_id
        return self._issue("register", username, algorithm, invite_id=invite_id)

    def register_complete(
        self,
        transaction_id: str,
        credential_id: str,
        public_key: bytes,
        policy_bytes: bytes,
        signature: bytes,
        device_id: str | None = None,
    ) -> None:
        self._check_ids(credential_id)
        if device_id is not None:
            self._check_ids(device_id)
        challenge = self._consume(transaction_id, "register")
        self._check_key(challenge.algorithm, public_key)
        policy = self._parse_policy(policy_bytes)
        message = self._message(
            Operation.REGISTER,
            challenge,
            credential_id,
            challenge.algorithm,
            policy.digest(),
            extra=hashlib.sha256(public_key).digest(),
        )
        if not crypto.verify(challenge.algorithm, public_key, message, signature):
            raise ProtocolError("invalid_signature", 401)
        now = self.clock()
        try:
            with Session(self.engine) as session, session.begin():
                # Spend the invite in the same transaction that creates the user:
                # concurrent completions on one invite cannot both succeed.
                spent = session.execute(
                    update(EnrollmentInvite)
                    .where(
                        EnrollmentInvite.invite_id == challenge.invite_id,
                        EnrollmentInvite.used_at.is_(None),
                        EnrollmentInvite.expires_at > now,
                    )
                    .values(used_at=now)
                )
                if spent.rowcount != 1:
                    raise ProtocolError("invalid_invite", 403)
                session.add(User(username=challenge.username, created_at=now))
                session.add(
                    Credential(
                        credential_id=credential_id,
                        username=challenge.username,
                        algorithm=challenge.algorithm,
                        public_key=public_key,
                        policy=policy_bytes,
                        policy_hash=policy.digest(),
                        status="active",
                        device_id=device_id,
                        created_at=now,
                    )
                )
        except IntegrityError as exc:
            raise ProtocolError("already_registered", 409) from exc

    # -- login -------------------------------------------------------------------

    def _active_credential(self, session: Session, credential_id: str) -> Credential:
        credential = session.get(Credential, credential_id)
        if credential is None or credential.status != "active":
            raise ProtocolError("unknown_credential", 404)
        return credential

    def login_start(self, username: str, credential_id: str | None = None) -> Started:
        with Session(self.engine) as session:
            query = select(Credential).where(
                Credential.username == username, Credential.status == "active"
            )
            if credential_id is not None:
                query = query.where(Credential.credential_id == credential_id)
            credential = session.scalars(query.order_by(Credential.created_at)).first()
            if credential is None:
                raise ProtocolError("unknown_credential", 404)
            return self._issue(
                "login", username, credential.algorithm, credential.credential_id
            )

    def login_complete(self, transaction_id: str, credential_id: str, signature: bytes) -> str:
        challenge = self._consume(transaction_id, "login")
        if credential_id != challenge.credential_id:
            raise ProtocolError("credential_mismatch", 400)
        with Session(self.engine) as session:
            credential = self._active_credential(session, credential_id)
            self._enforce_server_policy(credential, Operation.LOGIN)
            message = self._message(
                Operation.LOGIN,
                challenge,
                credential.credential_id,
                credential.algorithm,
                credential.policy_hash,
            )
            valid = crypto.verify(
                credential.algorithm, credential.public_key, message, signature
            )
        if not valid:
            raise ProtocolError("invalid_signature", 401)
        return secrets.token_urlsafe(32)

    def _enforce_server_policy(self, credential: Credential, operation: Operation) -> None:
        try:
            Policy.from_bytes(credential.policy).check(
                operation, self.rp_id, self.clock(), 0
            )
        except PolicyError as exc:
            raise ProtocolError("policy_violation", 403) from exc

    # -- migration -----------------------------------------------------------------

    def migrate_start(
        self, username: str, old_credential_id: str, new_algorithm: str = crypto.DEFAULT_ALGORITHM
    ) -> Started:
        if new_algorithm not in crypto.ALGORITHMS:
            raise ProtocolError("unsupported_algorithm", 422)
        with Session(self.engine) as session:
            credential = self._active_credential(session, old_credential_id)
            if credential.username != username:
                raise ProtocolError("unknown_credential", 404)
        return self._issue("migrate", username, new_algorithm, old_credential_id)

    def migrate_complete(
        self,
        transaction_id: str,
        new_credential_id: str,
        new_public_key: bytes,
        new_policy_bytes: bytes,
        old_signature: bytes,
        new_signature: bytes,
        new_device_id: str | None = None,
    ) -> str:
        """Activate a new credential authorized by the old one; revoke the old."""
        self._check_ids(new_credential_id)
        if new_device_id is not None:
            self._check_ids(new_device_id)
        challenge = self._consume(transaction_id, "migrate")
        self._check_key(challenge.algorithm, new_public_key)
        new_policy = self._parse_policy(new_policy_bytes)
        with Session(self.engine) as session:
            old = self._active_credential(session, challenge.credential_id)
            self._enforce_server_policy(old, Operation.MIGRATE)
            old_message = self._message(
                Operation.MIGRATE,
                challenge,
                old.credential_id,
                old.algorithm,
                old.policy_hash,
                extra=migration_binding(
                    new_credential_id, challenge.algorithm, new_public_key, new_policy.digest()
                ),
            )
            old_ok = crypto.verify(old.algorithm, old.public_key, old_message, old_signature)
            old_id, username = old.credential_id, old.username
        # The new key proves possession by signing a registration message that
        # carries the same transaction and challenge.
        proof = self._message(
            Operation.REGISTER,
            challenge,
            new_credential_id,
            challenge.algorithm,
            new_policy.digest(),
            extra=hashlib.sha256(new_public_key).digest(),
        )
        new_ok = crypto.verify(challenge.algorithm, new_public_key, proof, new_signature)
        if not (old_ok and new_ok):
            raise ProtocolError("invalid_signature", 401)
        now = self.clock()
        try:
            with Session(self.engine) as session, session.begin():
                result = session.execute(
                    update(Credential)
                    .where(Credential.credential_id == old_id, Credential.status == "active")
                    .values(status="revoked", replaced_by=new_credential_id)
                )
                if result.rowcount != 1:
                    raise ProtocolError("unknown_credential", 404)
                session.add(
                    Credential(
                        credential_id=new_credential_id,
                        username=username,
                        algorithm=challenge.algorithm,
                        public_key=new_public_key,
                        policy=new_policy_bytes,
                        policy_hash=new_policy.digest(),
                        status="active",
                        device_id=new_device_id,
                        created_at=now,
                    )
                )
        except IntegrityError as exc:
            raise ProtocolError("already_registered", 409) from exc
        return new_credential_id

    # -- inspection ----------------------------------------------------------------

    def credential_status(self, credential_id: str) -> tuple[str, str | None, str | None]:
        with Session(self.engine) as session:
            credential = session.get(Credential, credential_id)
            if credential is None:
                raise ProtocolError("unknown_credential", 404)
            return credential.status, credential.replaced_by, credential.device_id
