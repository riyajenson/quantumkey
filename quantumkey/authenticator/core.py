"""Structured-request signing core (the policy enforcement point).

Callers describe *what* they want signed (operation, relying party,
transaction, challenge, and for migration the target credential). The core
checks the credential's policy and builds the canonical message itself, so no
caller can obtain a signature over bytes of its own choosing. The same core
runs in-process (software signer) and inside the virtual token.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from quantumkey import crypto
from quantumkey.protocol.message import Operation, SignedMessage
from quantumkey.protocol.migration import migration_binding, revocation_binding
from quantumkey.protocol.policy import Policy, PolicyError

CHALLENGE_BYTES = 32


class SigningRefused(Exception):
    """The signer declined: policy violation, unknown credential, bad request."""


@dataclass(frozen=True)
class MigrationTarget:
    credential_id: str
    algorithm: str
    public_key: bytes
    policy_hash: bytes


@dataclass(frozen=True)
class SignRequest:
    operation: Operation
    rp_id: str
    transaction_id: str
    challenge: bytes
    target: MigrationTarget | None = None  # required for, and only for, MIGRATE and ENROLL
    revoke_target: str | None = None  # required for, and only for, REVOKE


@dataclass(frozen=True)
class PublicCredential:
    credential_id: str
    algorithm: str
    public_key: bytes
    policy: Policy


class Signer(Protocol):
    """Contract shared by software and (virtual) hardware signers."""

    device_id: str  # self-reported identity of the device holding the keys

    def create_credential(
        self, algorithm: str, policy: Policy, credential_id: str
    ) -> PublicCredential: ...

    def public_credential(self, credential_id: str) -> PublicCredential: ...

    def sign(self, credential_id: str, request: SignRequest) -> bytes: ...


@dataclass
class _Held:
    public: PublicCredential
    private_key: bytes


class SigningCore:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._held: dict[str, _Held] = {}
        self._sign_times: dict[str, list[float]] = {}

    def add(self, public: PublicCredential, private_key: bytes) -> None:
        self._held[public.credential_id] = _Held(public, private_key)

    def forget(self, credential_id: str) -> None:
        self._held.pop(credential_id, None)

    def create(self, algorithm: str, policy: Policy, credential_id: str) -> tuple[PublicCredential, bytes]:
        """Generate a keypair. Returns the public record and the private key
        for the caller to protect; the private key is also held by this core."""
        if credential_id in self._held:
            raise SigningRefused("credential already exists")
        try:
            public_key, private_key = crypto.generate_keypair(algorithm)
        except crypto.CryptoError as exc:
            raise SigningRefused(str(exc)) from exc
        public = PublicCredential(credential_id, algorithm, public_key, policy)
        self.add(public, private_key)
        return public, private_key

    def public(self, credential_id: str) -> PublicCredential:
        return self._get(credential_id).public

    def _get(self, credential_id: str) -> _Held:
        held = self._held.get(credential_id)
        if held is None:
            raise SigningRefused("unknown credential")
        return held

    def sign(self, credential_id: str, request: SignRequest) -> bytes:
        held = self._get(credential_id)
        public = held.public
        self._validate(request)
        now = self._clock()
        recent = [t for t in self._sign_times.get(credential_id, []) if now - t < 60]
        try:
            public.policy.check(request.operation, request.rp_id, now, len(recent))
        except PolicyError as exc:
            raise SigningRefused(f"policy: {exc}") from exc
        message = SignedMessage(
            operation=request.operation,
            rp_id=request.rp_id.encode(),
            transaction_id=request.transaction_id.encode(),
            challenge=request.challenge,
            credential_id=credential_id.encode(),
            algorithm=public.algorithm.encode(),
            policy_hash=public.policy.digest(),
            extra=self._extra(public, request),
        ).encode()
        signature = crypto.sign(public.algorithm, held.private_key, message)
        recent.append(now)
        self._sign_times[credential_id] = recent
        return signature

    @staticmethod
    def _validate(request: SignRequest) -> None:
        if len(request.challenge) != CHALLENGE_BYTES:
            raise SigningRefused("challenge must be 32 bytes")
        if not request.transaction_id or not request.rp_id:
            raise SigningRefused("transaction and relying party are required")
        adds_credential = request.operation in (Operation.MIGRATE, Operation.ENROLL)
        if adds_credential != (request.target is not None):
            raise SigningRefused(
                "a new-credential target is required for, and only for, migrate and enroll"
            )
        if (request.operation is Operation.REVOKE) != (request.revoke_target is not None):
            raise SigningRefused("a revoke target is required for, and only for, revoke")
        if request.revoke_target is not None and not request.revoke_target:
            raise SigningRefused("revoke target must not be empty")

    @staticmethod
    def _extra(public: PublicCredential, request: SignRequest) -> bytes:
        if request.operation is Operation.REGISTER:
            return hashlib.sha256(public.public_key).digest()
        if request.operation is Operation.REVOKE:
            return revocation_binding(request.revoke_target)
        if request.operation in (Operation.MIGRATE, Operation.ENROLL):
            target = request.target
            return migration_binding(
                target.credential_id, target.algorithm, target.public_key, target.policy_hash
            )
        return b""
