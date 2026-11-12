"""Bindings an existing credential signs to authorize an account change: a new
credential (migrate, enroll) or a revocation."""

from __future__ import annotations

import hashlib
import struct


def migration_binding(
    credential_id: str, algorithm: str, public_key: bytes, policy_hash: bytes
) -> bytes:
    """Length-prefixed SHA-256 over the new credential's identity and key."""
    digest = hashlib.sha256()
    for part in (credential_id.encode(), algorithm.encode(), public_key, policy_hash):
        digest.update(struct.pack(">I", len(part)))
        digest.update(part)
    return digest.digest()


def revocation_binding(target_credential_id: str) -> bytes:
    """Length-prefixed SHA-256 of the credential to revoke."""
    target = target_credential_id.encode()
    return hashlib.sha256(struct.pack(">I", len(target)) + target).digest()
