# QuantumKey API and Protocol Contract (v1)

**Status:** Implemented in `quantumkey/server/app.py` and `quantumkey/server/service.py`, and tested. Protocol version 1. This is a custom protocol, not WebAuthn.

## 1. Encoding rules

- JSON over HTTP(S). Unknown fields are rejected (HTTP 422).
- Binary values are base64url **without padding**. Padded or otherwise non-canonical encodings are rejected (`invalid_encoding`, 422).
- Identifiers (username, credential id) are printable and at most 64 characters.
- Errors are `{"error": "<code>"}` with the HTTP status listed in section 5.

## 2. Canonical signed message

```
DOMAIN     = "QuantumKey/v1" 0x00
operation  = 1 byte: 1 register | 2 login | 3 migrate
then 7 fields, each a 4-byte big-endian length + bytes, in this order:
  rp_id, transaction_id, challenge, credential_id, algorithm, policy_hash, extra
```

- `policy_hash` = SHA-256 of the credential's canonical policy JSON (sorted keys, no whitespace).
- `extra` depends on the operation:
  - **register:** SHA-256(public key). This is proof of possession bound to that key.
  - **login:** empty.
  - **migrate:** `migration_binding(new_credential_id, new_algorithm, new_public_key, new_policy_hash)`, a length-prefixed SHA-256 (`quantumkey/protocol/migration.py`).
- Fields are capped at 8192 bytes. The parser rejects a wrong domain, unknown operation, truncation and trailing bytes.
- The server **always rebuilds** this message from its own records and never accepts one from the client.
- ML-DSA's FIPS 204 context string is not used. Domain separation is inside the message (see `docs/decisions/0004-canonical-message.md`).

## 3. Endpoints

| Method | Route | Request | Response |
|---|---|---|---|
| GET | `/health` | — | `{status, protocol_version}` |
| POST | `/auth/register/start` | `{username, algorithm?}` | started object (below) |
| POST | `/auth/register/complete` | `{transaction_id, credential_id, public_key, policy, signature}` | 201 `{credential_id, status}` |
| POST | `/auth/login/start` | `{username, credential_id?}` | started object incl. `credential_id` |
| POST | `/auth/login/complete` | `{transaction_id, credential_id, signature}` | `{authenticated, session_token}` |
| POST | `/auth/migrate/start` | `{username, credential_id, algorithm?}` | started object incl. old `credential_id` |
| POST | `/auth/migrate/complete` | `{transaction_id, new_credential_id, new_public_key, new_policy, old_signature, new_signature}` | `{credential_id, status}` |
| GET | `/credentials/{id}` | — | `{credential_id, status, replaced_by}` |

The started object is `{protocol_version, operation, rp_id, transaction_id, challenge, expires_at, algorithm[, credential_id]}`.

## 4. Lifecycle rules

- A challenge is 32 random bytes with a 60 s TTL. It is bound to purpose, account, credential (login/migrate) and algorithm.
- A challenge is consumed by one conditional `UPDATE ... WHERE used_at IS NULL AND expires_at > now`, **before** signature checks. A failed attempt therefore burns it.
- Registration only creates new accounts. Adding a credential to an existing account requires migration, which the existing credential must authorize.
- Migration verifies two signatures: the old credential over the `migrate` message, and the new key over a `register` proof with the same transaction. It then revokes the old credential and inserts the new one in one transaction.
- The server re-checks the stored policy's RP, allowed operations and expiry on login and migrate.

## 5. Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_challenge` | 400 | Unknown, expired, reused or wrong-purpose transaction |
| `credential_mismatch` | 400 | Credential differs from the one the challenge was issued for |
| `invalid_signature` | 401 | Verification failed |
| `policy_violation` | 403 | Stored policy forbids the operation or has expired |
| `unknown_credential` | 404 | No active credential (also returned for an unknown user at login) |
| `user_exists` / `already_registered` | 409 | Account or credential id already exists |
| `invalid_encoding`, `invalid_identifier`, `invalid_public_key`, `invalid_policy`, `unsupported_algorithm` | 422 | Malformed input |

## 6. Open items

Direct revocation endpoint, session management for `session_token` (currently issued and not stored), server-side rate limiting, account recovery, and user-enumeration resistance at `/auth/login/start`.
