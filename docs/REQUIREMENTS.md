# QuantumKey Requirements

**Status:** Phase 1 baseline, reconciled with the prototype on 2026-11-06. "Evidence" names the test or file that demonstrates each requirement. "Open" means not yet met.

## 1. Scope

A research prototype of ML-DSA-based challenge-response authentication with a software signer, a token-style signer, and a migration path between them.

## 2. Non-goals (current prototype)

- WebAuthn/CTAP compatibility, browser integration, or third-party relying parties.
- Production deployment, TLS configuration, multi-tenant hardening.
- Real hardware, a GUI (Phase 7), mobile clients.
- Custom cryptographic primitives.
- Resistance to physical, side-channel, fault or supply-chain attacks.

## 3. Functional requirements

| ID | Requirement | Evidence |
|---|---|---|
| FR-01 | Use standardized ML-DSA-44/65/87 through pinned liboqs; default ML-DSA-65 | `quantumkey/crypto.py`; `phase2/requirements.lock.txt` |
| FR-02 | The authenticator generates key pairs locally | `SigningCore.create`; `test_register_and_login_for_every_variant` |
| FR-03 | Registration binds the public key to account, credential id, RP, policy and a one-time challenge through proof of possession | `RelyingParty.register_complete`; `test_registration_rejects_swapped_policy` |
| FR-04 | Login requires a fresh, random, expiring challenge | `test_expired_challenge_is_rejected` |
| FR-05 | Signatures cover a canonical, versioned, domain-separated message | `quantumkey/protocol/message.py`; protocol tests |
| FR-06 | The RP verifies with the registered public key and rebuilds the message itself | `RelyingParty._message` |
| FR-07 | Challenges are single-use and consumed atomically | `test_concurrent_completion_allows_exactly_one_success` |
| FR-08 | The RP never receives a private key | Data model has no private-key field; API payload review |
| FR-09 | Software private keys are stored only in the encrypted vault | `quantumkey/authenticator/vault.py`; `test_wrong_pin_cannot_sign_and_data_stays_private` |
| FR-10 | A credential can be migrated to another signer without key export; the old one is revoked | `tests/e2e/test_migration.py` |
| FR-11 | Credentials carry a signing policy enforced by the signer | `test_signer_enforces_rate_limit_and_expiry`; `test_token_enforces_policy_for_a_malicious_host` |
| FR-12 | Protocol and vault formats are versioned; older vaults are upgraded in place | `DOMAIN = b"QuantumKey/v1\0"`; vault `format_version`; `test_v2_vault_is_upgraded_in_place_and_still_unlocks` |
| FR-13 | Users can revoke a credential directly | **Open** (only migration revokes) |
| FR-14 | User presence / user verification is distinguished | **Open** |
| FR-15 | First registration of a username requires a single-use, expiring invite issued by the operator | `tests/server/test_enrollment.py` |
| FR-16 | Users can delete a credential from the vault and change the vault PIN | `cli delete`, `cli change-pin`; `tests/authenticator/` |

## 4. Security requirements

| ID | Requirement | Status |
|---|---|---|
| SEC-01 | CSPRNG for challenges, salts, nonces (`secrets`, `os.urandom`) | Met |
| SEC-02 | Challenge bound to RP, transaction, purpose, account/credential, expiry | Met |
| SEC-03 | Reject expired, unknown, reused and wrong-purpose challenges identically | Met (`invalid_challenge`) |
| SEC-04 | Consume the challenge before verification, so each challenge allows one attempt | Met |
| SEC-05 | Strict parsing: canonical base64url, unknown JSON fields rejected, length limits | Met |
| SEC-06 | Never log or transmit private keys, PINs or derived keys | Met by review. No logging of secrets exists |
| SEC-07 | Server-side rate limiting and request-size limits | Partial (field length limits; no rate limiting) |
| SEC-08 | Revocation, recovery and account-recovery abuse controls | Partial (revocation through migration only) |
| SEC-09 | Host, token, transport and server are treated as separate trust domains | Met in design; token is a process, not a device |
| SEC-10 | Limitations of software key storage are documented | Met (`docs/VAULT_SPECIFICATION.md`) |

## 5. Non-functional requirements

- **Latency:** interactive login under 1 s on the development machine (measured about 325 ms median).
- **Reproducibility:** pinned dependencies, documented setup, automated tests (`python -m pytest -q`).
- **Portability:** Windows 11 validated locally; Linux (Ubuntu, GitHub Actions) validated in CI. macOS open.
- **Migration:** server schema changes will need Alembic. Currently `create_all` only (open).
