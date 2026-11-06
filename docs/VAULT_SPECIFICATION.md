# QuantumKey Software Vault Specification (format v2)

**Status:** Implemented in `quantumkey/authenticator/vault.py`, and tested. The Phase 2 proof of concept (`phase2/vault.py`, format v1) is superseded.

## 1. Objectives

- Protect private keys at rest if the vault file is copied.
- Detect modification of a sealed key or of its credential id, algorithm or signing policy.
- Support multiple credentials, each usable independently.

## 2. Explicit limitations

The vault cannot protect a key when the host or authenticator process is compromised while unlocked, when the PIN is captured, or when process memory is read. It does not detect rollback to an older copy of the file. Python cannot reliably zeroize memory, so a decrypted key may linger until garbage collection. The software signer runs in the host process, so policy enforcement there can be bypassed by host malware.

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
| `format_version` | 2 | No |

There is no PIN, derived key or plaintext private key on disk (`test_wrong_pin_cannot_sign_and_data_stays_private`).

## 4. Cryptography

- **KDF:** Argon2id, time cost 3, memory 64 MiB, parallelism 1, 32-byte output, fresh 16-byte salt per credential. On the development machine one derivation takes about 256 ms, which is most of a login (`docs/evaluation/bench-2026-11-06.json`).
- **AEAD:** AES-256-GCM (pyca/cryptography), random 96-bit nonce. Each key encrypts exactly one message, so nonce reuse cannot occur.
- **Associated data:** `"QuantumKey-vault-v2" 0x00` followed by length-prefixed credential id, algorithm and SHA-256(policy). Editing any of these, or the ciphertext, makes unlock fail (`test_tampered_vault_policy_is_detected`).
- **Errors:** a wrong PIN and damaged data raise the same `VaultUnlockError`.

## 5. Lifecycle

| Operation | Behaviour |
|---|---|
| Create | Signer generates the key pair; vault seals and inserts; duplicate id raises `VaultError` |
| Use | Decrypt for one signing call, sign, drop the reference |
| List | Public metadata only; no PIN needed |
| Delete | Row removed (`Vault.delete`). SQLite pages and SSD wear-levelling may retain old bytes |
| Migrate | Old key authorizes a new credential in another signer (see API contract); the vault row stays until deleted |

## 6. Known gaps

- No failed-attempt counter. It could not stop offline guessing against a copied file anyway; a hardware token would be needed.
- No inactivity lock or unlocked session: every signature re-derives the key. This is safe but slow, and is a candidate for tuning.
- Argon2id parameters are not yet calibrated to a target unlock time, and there is no parameter-upgrade or re-wrap path.
- There is no schema migration tool beyond `format_version`.
