"""Phase 5: vault format v3 (per-credential KDF parameters), migration from v2,
PIN change, secure deletion."""

import os
import sqlite3

import pytest
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from quantumkey import crypto
from quantumkey.authenticator.vault import (
    DEFAULT_KDF,
    FORMAT_VERSION,
    KdfParams,
    Vault,
    VaultError,
    VaultUnlockError,
    _aad,
)
from quantumkey.protocol.policy import Policy

FAST = KdfParams(time_cost=1, memory_kib=8192, parallelism=1)


def keypair():
    return crypto.generate_keypair("ML-DSA-44")


def put(vault, pin="1234", credential_id="cred-1", kdf=None):
    public_key, private_key = keypair()
    vault.put(pin, credential_id, "ML-DSA-44", public_key, Policy(rp_id="rp"), private_key, kdf=kdf)
    return private_key


def columns(path, sql):
    with sqlite3.connect(path) as db:
        return db.execute(sql).fetchall()


def test_format_and_default_parameters():
    assert FORMAT_VERSION == 3
    assert DEFAULT_KDF == KdfParams(time_cost=3, memory_kib=65_536, parallelism=1)


def test_parameters_are_stored_per_credential(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    private_key = put(vault)
    assert columns(
        vault.path, "SELECT kdf_time_cost, kdf_memory_kib, kdf_parallelism, format_version FROM credentials"
    ) == [(1, 8192, 1, 3)]
    # A vault opened with different defaults still unlocks with the stored parameters.
    assert Vault(vault.path).unlock("1234", "cred-1") == private_key


def test_out_of_range_parameters_in_the_file_are_refused(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    put(vault)
    with sqlite3.connect(vault.path) as db:
        db.execute("UPDATE credentials SET kdf_memory_kib = 1 << 30")  # 1 TiB: would hang
    with pytest.raises(VaultError, match="KDF parameters"):
        vault.unlock("1234", "cred-1")


def test_constructor_rejects_out_of_range_parameters(tmp_path):
    with pytest.raises(VaultError):
        Vault(tmp_path / "v.sqlite3", kdf=KdfParams(time_cost=0, memory_kib=8192, parallelism=1))


def test_unknown_format_version_is_refused(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    put(vault)
    with sqlite3.connect(vault.path) as db:
        db.execute("UPDATE credentials SET format_version = 99")
    with pytest.raises(VaultError, match="format version"):
        vault.unlock("1234", "cred-1")


def _write_v2_vault(path, pin, credential_id, private_key, public_key, policy):
    """A vault exactly as format v2 wrote it: fixed Argon2id parameters, no KDF columns."""
    salt, nonce = os.urandom(16), os.urandom(12)
    key = hash_secret_raw(
        secret=pin.encode(), salt=salt, time_cost=3, memory_cost=65_536,
        parallelism=1, hash_len=32, type=Type.ID,
    )
    sealed = AESGCM(key).encrypt(nonce, private_key, _aad(credential_id, "ML-DSA-44", policy.digest()))
    with sqlite3.connect(path) as db:
        db.execute(
            """CREATE TABLE credentials (
                credential_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL,
                public_key BLOB NOT NULL, policy BLOB NOT NULL, salt BLOB NOT NULL,
                nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, format_version INTEGER NOT NULL)"""
        )
        db.execute(
            "INSERT INTO credentials VALUES (?, ?, ?, ?, ?, ?, ?, 2)",
            (credential_id, "ML-DSA-44", public_key, policy.canonical_bytes(), salt, nonce, sealed),
        )


def test_v2_vault_is_upgraded_in_place_and_still_unlocks(tmp_path):
    path = tmp_path / "old.sqlite3"
    public_key, private_key = keypair()
    _write_v2_vault(path, "1234", "cred-old", private_key, public_key, Policy(rp_id="rp"))
    vault = Vault(path, kdf=FAST)
    assert columns(
        path, "SELECT kdf_time_cost, kdf_memory_kib, kdf_parallelism, format_version FROM credentials"
    ) == [(3, 65_536, 1, 3)]
    assert vault.unlock("1234", "cred-old") == private_key
    Vault(path)  # opening again is a no-op
    assert columns(path, "SELECT count(*) FROM credentials") == [(1,)]


def test_change_pin_rewraps_every_credential_with_new_parameters(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    first, second = put(vault, credential_id="a"), put(vault, credential_id="b")
    stronger = KdfParams(time_cost=2, memory_kib=16_384, parallelism=1)
    vault.change_pin("1234", "5678", kdf=stronger)
    assert vault.unlock("5678", "a") == first and vault.unlock("5678", "b") == second
    with pytest.raises(VaultUnlockError):
        vault.unlock("1234", "a")
    assert set(columns(vault.path, "SELECT kdf_time_cost, kdf_memory_kib FROM credentials")) == {
        (2, 16_384)
    }


def test_change_pin_with_a_wrong_pin_changes_nothing(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    private_key = put(vault)
    before = columns(vault.path, "SELECT salt, nonce, ciphertext FROM credentials")
    with pytest.raises(VaultUnlockError):
        vault.change_pin("0000", "5678")
    assert columns(vault.path, "SELECT salt, nonce, ciphertext FROM credentials") == before
    assert vault.unlock("1234", "cred-1") == private_key


def test_change_pin_is_all_or_nothing_across_credentials(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    put(vault, credential_id="a")
    put(vault, pin="other", credential_id="b")  # sealed under a different PIN
    before = columns(vault.path, "SELECT credential_id, ciphertext FROM credentials ORDER BY 1")
    with pytest.raises(VaultUnlockError):
        vault.change_pin("1234", "5678")
    assert columns(vault.path, "SELECT credential_id, ciphertext FROM credentials ORDER BY 1") == before


def test_change_pin_rejects_an_empty_new_pin(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    put(vault)
    with pytest.raises(VaultError):
        vault.change_pin("1234", "")


def test_delete_needs_the_pin_and_removes_the_ciphertext_from_the_file(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    put(vault, credential_id="keep")
    put(vault, credential_id="gone")
    (sealed,) = columns(vault.path, "SELECT ciphertext FROM credentials WHERE credential_id = 'gone'")[0]
    with pytest.raises(VaultUnlockError):
        vault.delete("0000", "gone")
    vault.delete("1234", "gone")
    assert [c.credential_id for c in vault.list_credentials()] == ["keep"]
    assert sealed not in vault.path.read_bytes()  # secure_delete overwrote it


def test_delete_unknown_credential_raises_key_error(tmp_path):
    vault = Vault(tmp_path / "v.sqlite3", kdf=FAST)
    with pytest.raises(KeyError):
        vault.delete("1234", "nope")
