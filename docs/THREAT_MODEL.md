# QuantumKey Threat Model

**Status:** Phase 1 baseline, reconciled with the prototype on 2026-11-06. This is not a security audit.

## 1. Assets

ML-DSA private keys; the vault PIN and derived keys; public keys and credential-to-account bindings; challenges and transaction state; signing policies; session tokens; RP identity; token firmware (future).

## 2. Adversaries

Remote attacker without an account; network attacker; attacker with a copy of the vault or server database; malware running as the local user; a malicious host driving the token; an attacker attempting replay, race, downgrade or credential substitution; a physical attacker with a token (future); a supply-chain attacker (future).

## 3. Threats and status

| ID | Threat | Mitigation in the prototype | Evidence | Residual |
|---|---|---|---|---|
| T-01 | Challenge replay | Random 32-byte challenge, 60 s expiry, single use | `test_replayed_login_is_rejected`, `test_expired_challenge_is_rejected` | — |
| T-02 | Challenge race | Atomic conditional UPDATE before verification | `test_concurrent_completion_allows_exactly_one_success` | Tested on SQLite only |
| T-03 | RP confusion | `rp_id` in every signed message and in the policy; signer refuses other RPs | `test_signature_for_another_relying_party_is_rejected` | No origin binding to a browser |
| T-04 | Message ambiguity | Length-prefixed canonical encoding, domain tag, strict parser | protocol tests | No formal proof |
| T-05 | Credential substitution | Registration only for new accounts; additions only through old-key-authorized migration | migration tests | First registration of a username is unauthenticated |
| T-06 | Theft of a vault copy | Argon2id + AES-256-GCM per credential | vault tests | Offline PIN guessing; short PINs are weak |
| T-07 | Host compromise while unlocked | Token keeps keys out of the host process | token tests | Software signer offers no protection; token is only a process |
| T-08 | Signing-oracle abuse | **Structured-request signing**: the signer builds the message itself; the token rejects extra fields and has no raw-sign or export command | `test_token_has_no_export_or_raw_sign_command`, `test_token_enforces_policy_for_a_malicious_host` | A malicious host can still request a valid login for the policy's own RP |
| T-09 | Token parser exploit | Bounded frames (64 KiB), JSON object only, unknown fields rejected, type checks | `test_token_survives_garbage_frames` | No fuzzing yet |
| T-10 | Malicious firmware | Out of scope (no hardware) | — | Open |
| T-11 | Side-channel leakage | liboqs implementation; Windows build warns that constant time is not guaranteed | `phase2/DEVELOPMENT.md` | Open |
| T-12 | Policy swap | Policy hash bound into signatures and vault AAD | `test_registration_rejects_swapped_policy`, `test_tampered_vault_policy_is_detected` | — |
| T-13 | Cross-operation replay | Operation byte in the message; migration needs a `migrate` signature | `test_signature_for_one_operation_is_useless_for_another` | — |
| T-14 | Algorithm downgrade | Algorithm in the signed message; the server fixes it at start | message tests | — |
| T-15 | Session token theft | Not addressed (token not stored or verified) | — | Open |
| T-16 | User enumeration | Not addressed (`/auth/login/start` returns 404 for unknown users) | — | Open |

## 4. Explicit exclusions

Physical, fault-injection and side-channel attacks; compromised liboqs or Python runtime; denial of service; TLS configuration.

## 5. Risk register (top items)

1. **The software signer gives no host-compromise protection.** Mitigation: a real token (Phase 8).
2. **Unauthenticated first registration.** Mitigation: tie enrollment to an existing account login or an out-of-band invite.
3. **Timing-safety warning in the Windows build.** Mitigation: the Linux GCC Release build in CI shows no warning; that build is not verified constant time.
4. **No formal analysis of the message and migration protocol.** Mitigation: Tamarin/ProVerif model.
