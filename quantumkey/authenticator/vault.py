"""PIN-protected multi-credential vault (SQLite, Argon2id, AES-256-GCM).

Each credential's private key is sealed under its own key derived from the PIN
with a fresh salt and that credential's stored Argon2id parameters. The
credential id, algorithm, and signing-policy hash are authenticated data, so
editing any of them in the file makes unlocking fail. Deleted and re-wrapped
rows are overwritten in the file (SQLite secure_delete). This is software
protection of data at rest only: malware running while the vault is unlocked
can still use or extract the key.
"""

from __future__ import annotations

import os
import sqlite3
import struct
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumkey.protocol.policy import Policy

FORMAT_VERSION = 3


class VaultError(Exception):
    """Base class for vault failures."""


class VaultUnlockError(VaultError):
    """Wrong PIN or modified vault data (deliberately indistinguishable)."""


@dataclass(frozen=True)
class KdfParams:
    """Argon2id cost parameters, stored with each credential."""

    time_cost: int
    memory_kib: int
    parallelism: int

    def check(self) -> None:
        """Bound the parameters, so a damaged or hostile vault file cannot make
        an unlock run for hours or exhaust memory."""
        values = (self.time_cost, self.memory_kib, self.parallelism)
        if (
            any(isinstance(v, bool) or not isinstance(v, int) for v in values)
            or not 1 <= self.time_cost <= 10
            or not 8_192 <= self.memory_kib <= 1_048_576
            or not 1 <= self.parallelism <= 8
        ):
            raise VaultError(f"KDF parameters out of range: {values}")


DEFAULT_KDF = KdfParams(time_cost=3, memory_kib=65_536, parallelism=1)
_V2_KDF = KdfParams(time_cost=3, memory_kib=65_536, parallelism=1)  # fixed in format v2


@dataclass(frozen=True)
class StoredCredential:
    credential_id: str
    algorithm: str
    public_key: bytes
    policy: Policy


def _derive(pin: str, salt: bytes, kdf: KdfParams) -> bytes:
    if not pin:
        raise VaultError("PIN must not be empty")
    kdf.check()
    return hash_secret_raw(
        secret=pin.encode("utf-8"),
        salt=salt,
        time_cost=kdf.time_cost,
        memory_cost=kdf.memory_kib,
        parallelism=kdf.parallelism,
        hash_len=32,
        type=Type.ID,
    )


def _aad(credential_id: str, algorithm: str, policy_hash: bytes) -> bytes:
    """Length-prefixed, so no field value can be confused with a separator.
    Unchanged from format v2, so upgraded rows still open."""
    parts = [b"QuantumKey-vault-v2\x00"]
    for field in (credential_id.encode(), algorithm.encode(), policy_hash):
        parts.append(struct.pack(">I", len(field)) + field)
    return b"".join(parts)


@dataclass(frozen=True)
class _Row:
    credential_id: str
    algorithm: str
    public_key: bytes
    policy: bytes
    salt: bytes
    nonce: bytes
    ciphertext: bytes
    format_version: int
    kdf: KdfParams


_COLUMNS = (
    "credential_id, algorithm, public_key, policy, salt, nonce, ciphertext, format_version, "
    "kdf_time_cost, kdf_memory_kib, kdf_parallelism"
)


class Vault:
    def __init__(self, path: str | Path, kdf: KdfParams = DEFAULT_KDF) -> None:
        kdf.check()
        self.path = Path(path)
        self.kdf = kdf
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT PRIMARY KEY,
                    algorithm TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    policy BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    format_version INTEGER NOT NULL,
                    kdf_time_cost INTEGER NOT NULL,
                    kdf_memory_kib INTEGER NOT NULL,
                    kdf_parallelism INTEGER NOT NULL
                )"""
            )
            self._upgrade_v2(db)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        """One transaction on a connection that overwrites deleted content."""
        db = sqlite3.connect(self.path, isolation_level=None)
        try:
            db.execute("PRAGMA secure_delete = ON")
            db.execute("BEGIN")
            try:
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
        finally:
            db.close()

    @staticmethod
    def _upgrade_v2(db: sqlite3.Connection) -> None:
        """Format v2 had no KDF columns and always used _V2_KDF. Add the columns
        with those values; the sealed keys and associated data are unchanged."""
        columns = {row[1] for row in db.execute("PRAGMA table_info(credentials)")}
        if "kdf_time_cost" in columns:
            return
        for name, value in (
            ("kdf_time_cost", _V2_KDF.time_cost),
            ("kdf_memory_kib", _V2_KDF.memory_kib),
            ("kdf_parallelism", _V2_KDF.parallelism),
        ):
            db.execute(f"ALTER TABLE credentials ADD COLUMN {name} INTEGER NOT NULL DEFAULT {value}")
        db.execute("UPDATE credentials SET format_version = 3 WHERE format_version = 2")

    @staticmethod
    def _seal(
        pin: str, credential_id: str, algorithm: str, policy_hash: bytes, private_key: bytes,
        kdf: KdfParams,
    ) -> tuple[bytes, bytes, bytes]:
        salt, nonce = os.urandom(16), os.urandom(12)
        sealed = AESGCM(_derive(pin, salt, kdf)).encrypt(
            nonce, private_key, _aad(credential_id, algorithm, policy_hash)
        )
        return salt, nonce, sealed

    def put(
        self,
        pin: str,
        credential_id: str,
        algorithm: str,
        public_key: bytes,
        policy: Policy,
        private_key: bytes,
        kdf: KdfParams | None = None,
    ) -> None:
        kdf = kdf or self.kdf
        salt, nonce, sealed = self._seal(
            pin, credential_id, algorithm, policy.digest(), private_key, kdf
        )
        row = (
            credential_id, algorithm, public_key, policy.canonical_bytes(), salt, nonce, sealed,
            FORMAT_VERSION, kdf.time_cost, kdf.memory_kib, kdf.parallelism,
        )
        try:
            with self._db() as db:
                db.execute(f"INSERT INTO credentials ({_COLUMNS}) VALUES ({', '.join('?' * 11)})", row)
        except sqlite3.IntegrityError as exc:
            raise VaultError(f"credential already exists: {credential_id}") from exc

    def _rows(self, credential_id: str | None = None) -> list[_Row]:
        query = f"SELECT {_COLUMNS} FROM credentials"
        args: tuple = ()
        if credential_id is not None:
            query, args = query + " WHERE credential_id = ?", (credential_id,)
        with self._db() as db:
            rows = db.execute(query + " ORDER BY credential_id", args).fetchall()
        return [_Row(*r[:8], KdfParams(*r[8:])) for r in rows]

    def _row(self, credential_id: str) -> _Row:
        rows = self._rows(credential_id)
        if not rows:
            raise KeyError(credential_id)
        return rows[0]

    def get_public(self, credential_id: str) -> StoredCredential:
        row = self._row(credential_id)
        return StoredCredential(
            row.credential_id, row.algorithm, row.public_key, Policy.from_bytes(row.policy)
        )

    def list_credentials(self) -> list[StoredCredential]:
        return [
            StoredCredential(r.credential_id, r.algorithm, r.public_key, Policy.from_bytes(r.policy))
            for r in self._rows()
        ]

    @staticmethod
    def _open(pin: str, row: _Row) -> bytes:
        if row.format_version != FORMAT_VERSION:
            raise VaultError(f"unsupported vault format version: {row.format_version}")
        try:
            policy_hash = Policy.from_bytes(row.policy).digest()
            return AESGCM(_derive(pin, row.salt, row.kdf)).decrypt(
                row.nonce, row.ciphertext, _aad(row.credential_id, row.algorithm, policy_hash)
            )
        except (InvalidTag, ValueError) as exc:
            raise VaultUnlockError("PIN is incorrect or vault data is damaged") from exc

    def unlock(self, pin: str, credential_id: str) -> bytes:
        return self._open(pin, self._row(credential_id))

    def change_pin(self, old_pin: str, new_pin: str, kdf: KdfParams | None = None) -> int:
        """Re-seal every credential under `new_pin` (and `kdf`, default this
        vault's parameters). All credentials must open with `old_pin`; if any
        does not, nothing is changed. Returns the number of credentials."""
        if not new_pin:
            raise VaultError("PIN must not be empty")
        kdf = kdf or self.kdf
        kdf.check()
        resealed = []
        for row in self._rows():
            private_key = self._open(old_pin, row)
            policy_hash = Policy.from_bytes(row.policy).digest()
            salt, nonce, sealed = self._seal(
                new_pin, row.credential_id, row.algorithm, policy_hash, private_key, kdf
            )
            resealed.append(
                (salt, nonce, sealed, kdf.time_cost, kdf.memory_kib, kdf.parallelism,
                 row.credential_id, row.ciphertext)
            )
        with self._db() as db:
            for values in resealed:
                updated = db.execute(
                    "UPDATE credentials SET salt = ?, nonce = ?, ciphertext = ?, kdf_time_cost = ?, "
                    "kdf_memory_kib = ?, kdf_parallelism = ? WHERE credential_id = ? AND ciphertext = ?",
                    values,
                ).rowcount
                if updated != 1:  # changed by someone else since we read it
                    raise VaultError("vault changed during PIN change; nothing was modified")
        return len(resealed)

    def delete(self, pin: str, credential_id: str) -> None:
        """Remove a credential after confirming the PIN opens it. The row's
        bytes are overwritten in the database file; copies elsewhere (backups,
        SSD wear-levelling) are not."""
        self.unlock(pin, credential_id)  # KeyError if unknown, VaultUnlockError if wrong PIN
        with self._db() as db:
            db.execute("DELETE FROM credentials WHERE credential_id = ?", (credential_id,))
