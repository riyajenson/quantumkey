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
operation  = 1 byte: 1 register | 2 login | 3 migrate | 4 enroll | 5 revoke
then 7 fields, each a 4-byte big-endian length + bytes, in this order:
  rp_id, transaction_id, challenge, credential_id, algorithm, policy_hash, extra
```

- `policy_hash` = SHA-256 of the credential's canonical policy JSON (sorted keys, no whitespace).
- `extra` depends on the operation:
  - **register:** SHA-256(public key). This is proof of possession bound to that key.
  - **login:** empty.
  - **migrate** and **enroll:** `migration_binding(new_credential_id, new_algorithm, new_public_key, new_policy_hash)`, a length-prefixed SHA-256 (`quantumkey/protocol/migration.py`). The operation byte keeps the two apart.
  - **revoke:** `revocation_binding(target_credential_id)`, a length-prefixed SHA-256 of the credential to revoke.
- Fields are capped at 8192 bytes. The parser rejects a wrong domain, unknown operation, truncation and trailing bytes.
- The server **always rebuilds** this message from its own records and never accepts one from the client.
- ML-DSA's FIPS 204 context string is not used. Domain separation is inside the message (see `docs/decisions/0004-canonical-message.md`).

## 3. Endpoints

| Method | Route | Request | Response |
|---|---|---|---|
| GET | `/health` | — | `{status, protocol_version}` |
| POST | `/auth/register/start` | `{username, invite, algorithm?}` | started object (below) |
| POST | `/auth/register/complete` | `{transaction_id, credential_id, public_key, policy, signature, device_id?}` | 201 `{credential_id, status}` |
| POST | `/auth/login/start` | `{username, credential_id?}` | started object incl. `credential_id` |
| POST | `/auth/login/complete` | `{transaction_id, credential_id, signature}` | `{authenticated, session_token}` |
| GET | `/auth/session` | header `Authorization: Bearer <session_token>` | `{username, credential_id, expires_at}` |
| POST | `/auth/logout` | `{}` and the bearer header | `{status: "logged_out"}` |
| POST | `/auth/migrate/start` | `{username, credential_id, algorithm?}` | started object incl. old `credential_id` |
| POST | `/auth/migrate/complete` | `{transaction_id, new_credential_id, new_public_key, new_policy, old_signature, new_signature, new_device_id?}` | `{credential_id, status}` |
| POST | `/auth/enroll/start` | `{username, credential_id, algorithm?}` (`credential_id` authorizes) | started object incl. the authorizer's `credential_id` |
| POST | `/auth/enroll/complete` | `{transaction_id, new_credential_id, new_public_key, new_policy, authorizer_signature, new_signature, new_device_id?}` | `{credential_id, status: "active"}` |
| POST | `/auth/revoke/start` | `{username, credential_id}` (`credential_id` authorizes) | started object incl. the authorizer's `credential_id` |
| POST | `/auth/revoke/complete` | `{transaction_id, target_credential_id, signature}` | `{credential_id, status: "revoked"}` |
| GET | `/credentials/{id}` | — | `{credential_id, status, replaced_by, device_id}` |

The started object is `{protocol_version, operation, rp_id, transaction_id, challenge, expires_at, algorithm[, credential_id]}`.

## 4. Lifecycle rules

- A challenge is 32 random bytes with a 60 s TTL. It is bound to purpose, account, credential (login/migrate) and algorithm.
- A challenge is consumed by one conditional `UPDATE ... WHERE used_at IS NULL AND expires_at > now`, **before** signature checks. A failed attempt therefore burns it.
- Registration requires a single-use invite bound to the username, issued by the operator (`python -m quantumkey.server.admin invite <username>`, default lifetime 24 h). Only the token's SHA-256 is stored. `register/start` checks the invite before the username, so without a valid invite a taken name is indistinguishable from any other refusal. `register/complete` spends the invite in the same transaction that creates the account, after the signature verifies: a failed signature leaves the invite usable, and concurrent completions on one invite allow exactly one.
- `device_id` / `new_device_id` (optional, at most 64 characters) name the device that holds the new credential: the vault's or virtual token's random id. The server stores and reports it but cannot verify it: it is self-reported, not signed and not an attestation.
- A successful login opens a session for one hour. Only the token's SHA-256 is stored. A missing, malformed, unknown, expired or logged-out token is `invalid_session` (401). Migration ends the old credential's sessions; expired sessions are purged with the other expired rows.
- Registration only creates new accounts. An existing credential changes the account by signing: `migrate` replaces it, `enroll` adds another credential and keeps it (both verify the new key's `register` proof over the same transaction), and `revoke` revokes any active credential of the account, itself included. The authorizer's stored policy must allow the operation. Revocation locks the account row, rechecks that the authorizer is still active, refuses the account's last active credential, and ends the target's sessions (ADR 0009).
- Migration verifies two signatures: the old credential over the `migrate` message, and the new key over a `register` proof with the same transaction. It then revokes the old credential and inserts the new one in one transaction.
- The server re-checks the stored policy's RP, allowed operations and expiry on login and migrate.
- Every POST under `/auth/` counts toward a limit of 60 per client IP per minute (the window starts at that IP's first request) and must send a `Content-Length` of at most 64 KB. Both checks run before the body is read. The counts are per server process and reset on restart; the client IP is the socket peer (X-Forwarded-For is not trusted).
- Expired challenges and expired or used invites are deleted at most once a minute when a challenge is issued, and by `python -m quantumkey.server.admin purge`.

## 5. Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `invalid_challenge` | 400 | Unknown, expired, reused or wrong-purpose transaction |
| `credential_mismatch` | 400 | Credential differs from the one the challenge was issued for |
| `invalid_signature` | 401 | Verification failed |
| `invalid_session` | 401 | No live session for the bearer token |
| `policy_violation` | 403 | Stored policy forbids the operation or has expired |
| `invalid_invite` | 403 | Unknown, expired, used, or other-username invite (all identical) |
| `unknown_credential` | 404 | No active credential (also returned for an unknown user at login) |
| `user_exists` / `already_registered` | 409 | Account or credential id already exists |
| `last_credential` | 409 | The revocation would leave the account with no active credential |
| `length_required` | 411 | POST under `/auth/` without a `Content-Length` |
| `request_too_large` | 413 | Body larger than 64 KB |
| `invalid_encoding`, `invalid_identifier`, `invalid_public_key`, `invalid_policy`, `unsupported_algorithm` | 422 | Malformed input |
| `rate_limited` | 429 | Over 60 POSTs under `/auth/` from this IP in the current minute; `Retry-After` gives the seconds to wait |

## 6. Open items

Rate limits shared across server processes, account recovery, and user-enumeration resistance at `/auth/login/start`.
