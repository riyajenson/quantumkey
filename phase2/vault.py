"""Small encrypted-vault proof of concept for the Phase 2 experiment."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class VaultEnvelope:
    salt: bytes
    nonce: bytes
    ciphertext: bytes


class VaultUnlockError(ValueError):
    """Raised when a PIN is wrong or the encrypted record was modified."""


class CredentialVault:
    """Experimental PIN-based key wrapping; not a production vault."""

    ARGON2_TIME_COST = 3
    ARGON2_MEMORY_KIB = 65_536
    ARGON2_PARALLELISM = 1
    KEY_BYTES = 32

    @classmethod
    def _derive_key(cls, pin: str, salt: bytes) -> bytes:
        if not pin:
            raise ValueError("PIN must not be empty")
        return hash_secret_raw(
            secret=pin.encode("utf-8"),
            salt=salt,
            time_cost=cls.ARGON2_TIME_COST,
            memory_cost=cls.ARGON2_MEMORY_KIB,
            parallelism=cls.ARGON2_PARALLELISM,
            hash_len=cls.KEY_BYTES,
            type=Type.ID,
        )

    @classmethod
    def seal(
        cls, pin: str, private_key: bytes, credential_id: str, algorithm: str
    ) -> VaultEnvelope:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = cls._derive_key(pin, salt)
        aad = cls._associated_data(credential_id, algorithm)
        ciphertext = AESGCM(key).encrypt(nonce, private_key, aad)
        return VaultEnvelope(salt=salt, nonce=nonce, ciphertext=ciphertext)

    @classmethod
    def open(
        cls,
        pin: str,
        envelope: VaultEnvelope,
        credential_id: str,
        algorithm: str,
    ) -> bytes:
        key = cls._derive_key(pin, envelope.salt)
        try:
            return AESGCM(key).decrypt(
                envelope.nonce,
                envelope.ciphertext,
                cls._associated_data(credential_id, algorithm),
            )
        except InvalidTag as exc:
            raise VaultUnlockError("PIN is incorrect or vault data is damaged") from exc

    @staticmethod
    def _associated_data(credential_id: str, algorithm: str) -> bytes:
        return f"QuantumKey-v1\0{credential_id}\0{algorithm}".encode("utf-8")


class SQLiteCredentialVault:
    """Minimal persistent encrypted-vault experiment for local credentials."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL
                )"""
            )

    def put(
        self, credential_id: str, algorithm: str, pin: str, private_key: bytes
    ) -> None:
        envelope = CredentialVault.seal(pin, private_key, credential_id, algorithm)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """INSERT INTO credentials
                   (credential_id, algorithm, salt, nonce, ciphertext)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    credential_id,
                    algorithm,
                    envelope.salt,
                    envelope.nonce,
                    envelope.ciphertext,
                ),
            )

    def get(self, credential_id: str, pin: str) -> bytes:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT algorithm, salt, nonce, ciphertext "
                "FROM credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
        if row is None:
            raise KeyError(credential_id)
        algorithm = row[0]
        envelope = VaultEnvelope(salt=row[1], nonce=row[2], ciphertext=row[3])
        return CredentialVault.open(pin, envelope, credential_id, algorithm)

    def list_credentials(self) -> list[tuple[str, str]]:
        with sqlite3.connect(self.path) as connection:
            rows = connection.execute(
                "SELECT credential_id, algorithm FROM credentials ORDER BY credential_id"
            ).fetchall()
        return [(row[0], row[1]) for row in rows]
