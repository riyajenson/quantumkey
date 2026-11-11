# QuantumKey Software Vault Specification (format v3)

**Status:** Implemented in `quantumkey/authenticator/vault.py` and tested (`tests/authenticator/`). Format v2 vaults are upgraded in place when opened. The Phase 2 proof of concept (`phase2/vault.py`, format v1) is superseded.

## 1. Objectives

- Protect private keys at rest if the vault file is copied.
- Detect modification of a sealed key or of its credential id, algorithm or signing policy.
- Support multiple credentials, each usable independently.
- Allow the PIN and the Argon2id cost to change without re-enrolling.

## 2. Explicit limitations

The vault cannot protect a key when the host or authenticator process is compromised while unlocked, when the PIN is captured, or when process memory is read. It does not detect rollback to an older copy of the file. Python cannot reliably zeroize memory, so a decrypted key may linger until garbage collection, and an unlocked session (section 5) deliberately keeps it in memory for its lifetime. The software signer runs in the host process, so policy enforcement there can be bypassed by host malware.

## 3. Storage model

One SQLite table, `credentials`:

| Column | Content | Secret? |
|---|---|---|
| `credential_id` | Primary key | No |
| `algorithm` | ML-DSA variant name | No |
| `public_key` | Raw public key | No |
| `policy` | Canonical policy JSON | No (integrity-protected) |
| `salt` | 16 random bytes, per credential | No |
| `nonce` | 12 random bytes, per credential | No |
| `ciphertext` | AES-256-GCM(private key) including the tag | Encrypted |
| `format_version` | 3 | No |
| `kdf_time_cost`, `kdf_memory_kib`, `kdf_parallelism` | Argon2id parameters this row was sealed with | No |

There is no PIN, derived key or plaintext private key on disk (`test_wrong_pin_cannot_sign_and_data_stays_private`). Every connection sets `PRAGMA secure_delete = ON`, so deleted and re-wrapped rows are overwritten in the file (`test_delete_needs_the_pin_and_removes_the_ciphertext_from_the_file`).

## 4. Cryptography

- **KDF:** Argon2id, 32-byte output, fresh 16-byte salt per credential. New credentials use the vault's parameters, default time cost 3, memory 64 MiB, parallelism 1. On the development machine one derivation takes about 256 ms, which is most of a login (`docs/evaluation/bench-2026-11-06.json`). Parameters read from the file must lie within time cost 1-10, memory 8 MiB-1 GiB and parallelism 1-8, so a damaged or hostile file cannot make an unlock hang. Lowering them in the file only changes the derived key, so unlock fails.
- **AEAD:** AES-256-GCM (pyca/cryptography), random 96-bit nonce. Each key encrypts exactly one message, so nonce reuse cannot occur.
- **Associated data:** `"QuantumKey-vault-v2" 0x00` followed by length-prefixed credential id, algorithm and SHA-256(policy). The label is unchanged in v3 so upgraded rows still open. Editing any of these fields, or the ciphertext, makes unlock fail (`test_tampered_vault_policy_is_detected`).
- **Errors:** a wrong PIN and damaged data raise the same `VaultUnlockError`.

## 5. Lifecycle

| Operation | Behaviour |
|---|---|
| Create | Signer generates the key pair; vault seals and inserts; duplicate id raises `VaultError` |
| Use | Decrypt, sign, drop the reference. With `SoftwareSigner(unlock_ttl=N)` the key stays in memory for N seconds after the unlock (not after the last use), skipping Argon2id for further signatures; `lock()` ends all sessions. Default 0: no session. Policy is checked on every signature |
| List | Public metadata only; no PIN needed |
| Change PIN | `Vault.change_pin` / `cli change-pin`: every credential must open with the old PIN, then all are re-sealed with new salts and nonces under the new PIN and the vault's current parameters in one transaction. This is also how parameters are upgraded. On any failure nothing changes |
| Delete | `Vault.delete` / `cli delete`: the PIN must open the credential first; the row is then removed and overwritten in the file. Copies elsewhere (backups, SSD wear-levelling) are not. The credential stays active on the server, which has no revoke endpoint |
| Migrate | Old key authorizes a new credential in another signer (see API contract); the vault row stays until deleted |
| Upgrade | Opening a v2 vault adds the three KDF columns with the v2 parameters and sets `format_version` to 3. Keys and associated data are untouched. Unknown versions are refused on unlock |

## 6. Known gaps

- No failed-attempt counter. It could not stop offline guessing against a copied file anyway; a hardware token would be needed.
- Argon2id parameters are not yet calibrated to a target unlock time on target devices (experiment E-04); the mechanism to change them exists.
- No device identity: the server has no field for one, so adding it is a protocol change.
- Sessions live in one process. The CLI starts a new process per command, so it never benefits from them; a long-running client (the planned GUI) would.
