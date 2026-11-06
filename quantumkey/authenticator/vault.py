"""PIN-protected multi-credential vault (SQLite, Argon2id, AES-256-GCM).

Each credential's private key is sealed under its own key derived from the PIN
with a fresh salt. The credential id, algorithm, and signing-policy hash are
authenticated data, so editing any of them in the file makes unlocking fail.
This is software protection of data at rest only: malware running while the
vault is unlocked can still use or extract the key.
"""

from __future__ import annotations

import os
import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumkey.protocol.policy import Policy

FORMAT_VERSION = 2
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 65_536
ARGON2_PARALLELISM = 1


class VaultError(Exception):
    """Base class for vault failures."""


class VaultUnlockError(VaultError):
    """Wrong PIN or modified vault data (deliberately indistinguishable)."""


@dataclass(frozen=True)
class StoredCredential:
    credential_id: str
    algorithm: str
    public_key: bytes
    policy: Policy


def _derive(pin: str, salt: bytes) -> bytes:
    if not pin:
        raise VaultError("PIN must not be empty")
    return hash_secret_raw(
        secret=pin.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )


def _aad(credential_id: str, algorithm: str, policy_hash: bytes) -> bytes:
    """Length-prefixed, so no field value can be confused with a separator."""
    parts = [b"QuantumKey-vault-v2\x00"]
    for field in (credential_id.encode(), algorithm.encode(), policy_hash):
        parts.append(struct.pack(">I", len(field)) + field)
    return b"".join(parts)


class Vault:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    policy BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    format_version INTEGER NOT NULL
                )"""
            )

    def put(
        self,
        pin: str,
        credential_id: str,
        algorithm: str,
        public_key: bytes,
        policy: Policy,
        private_key: bytes,
    ) -> None:
        salt, nonce = os.urandom(16), os.urandom(12)
        sealed = AESGCM(_derive(pin, salt)).encrypt(
            nonce, private_key, _aad(credential_id, algorithm, policy.digest())
        )
        row = (
            credential_id,
            algorithm,
            public_key,
            policy.canonical_bytes(),
            salt,
            nonce,
            sealed,
            FORMAT_VERSION,
        )
        try:
            with sqlite3.connect(self.path) as db:
                db.execute("INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row)
        except sqlite3.IntegrityError as exc:
            raise VaultError(f"credential already exists: {credential_id}") from exc

    def _row(self, credential_id: str) -> tuple:
        with sqlite3.connect(self.path) as db:
            row = db.execute(
                "SELECT credential_id, algorithm, public_key, policy, salt, nonce, ciphertext, "
                "format_version FROM credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        if row is None:
            raise KeyError(credential_id)
        return row

    def get_public(self, credential_id: str) -> StoredCredential:
        cid, algorithm, public_key, policy, *_ = self._row(credential_id)
        return StoredCredential(cid, algorithm, public_key, Policy.from_bytes(policy))

    def list_credentials(self) -> list[StoredCredential]:
        with sqlite3.connect(self.path) as db:
            ids = [r[0] for r in db.execute("SELECT credential_id FROM credentials ORDER BY credential_id")]
        return [self.get_public(i) for i in ids]

    def unlock(self, pin: str, credential_id: str) -> bytes:
        cid, algorithm, _pk, policy, salt, nonce, sealed, version = self._row(credential_id)
        if version != FORMAT_VERSION:
            raise VaultError(f"unsupported vault format version: {version}")
        try:
            policy_hash = Policy.from_bytes(policy).digest()
            return AESGCM(_derive(pin, salt)).decrypt(
                nonce, sealed, _aad(cid, algorithm, policy_hash)
            )
        except (InvalidTag, ValueError) as exc:
            raise VaultUnlockError("PIN is incorrect or vault data is damaged") from exc

    def delete(self, credential_id: str) -> None:
        with sqlite3.connect(self.path) as db:
            db.execute("DELETE FROM credentials WHERE credential_id = ?", (credential_id,))
