# QuantumKey Research Notes

**Status:** Prototype results as of 2026-11-06. Claims below are *candidate*, not established novelty (see "Prior art").

## What the prototype demonstrates

A working relying party (FastAPI/SQLAlchemy), a PIN-protected multi-credential vault, a software signer, a virtual token process, and a CLI, covering register, login and migrate for ML-DSA-44/65/87. The automated suite (`python -m pytest -q`) covers the protocol, challenge lifecycle, hardening, end to end, migration and the token.

### Contribution 1 — structured-request signing

The signer's API has no "sign these bytes" call. A caller describes the operation (type, relying party, transaction, challenge, and for migration the target credential); the signer enforces the credential's policy and builds the canonical message itself (`quantumkey/authenticator/core.py`). The virtual token's wire protocol has no export command and rejects any extra field, so a host cannot request a signature over bytes it chose (tests: `test_token_has_no_export_or_raw_sign_command`, `test_token_enforces_policy_for_a_malicious_host`).

**Boundary of the claim.** This protects against a host that can only talk to a separate signer (the token). The *software* signer shares a process with the host, so malware there can bypass it. The value is a signing contract that stays identical when signing moves to real hardware.

### Contribution 2 — credential-bound policy

A canonical policy (relying party, allowed operations, expiry, rate limit) is hashed into the registration message and into every later signed message and into the vault's authenticated data. Swapping the policy at registration fails verification (401); editing it in the vault file makes unlocking fail. The server enforces relying party, operations and expiry; the signer additionally enforces the rate limit (it is per-process memory in the software signer and resets on restart).

### Contribution 3 — migration without key export

The old credential signs a binding over the new credential's id, algorithm, public key and policy hash, and the new key signs a proof of possession over the same transaction. The server then atomically revokes the old and activates the new credential in one database transaction. Tests cover software to token for all three variants, denial by policy, and failure leaving the old credential active. Because the algorithm is a parameter of the new credential, the same mechanism rotates a credential to a different ML-DSA parameter set (algorithm agility through migration).

### Evaluation (first numbers)

`docs/evaluation/bench-2026-11-06.json` (20 iterations per variant, in-process HTTP, Windows, unoptimized liboqs build):

| Variant | keygen / sign / verify (median ms) | login end to end (median ms) | login request+response JSON (bytes) |
|---|---|---|---|
| ML-DSA-44 | 0.53 / 2.52 / 0.62 | 328 | 3,706 |
| ML-DSA-65 | 0.96 / 3.35 / 1.08 | 325 | 4,890 |
| ML-DSA-87 | 1.53 / 4.43 / 1.74 | 322 | 6,649 |

Findings: (1) the ML-DSA operations are a small fraction of login time; about 256 ms of each login is the Argon2id vault unlock, so vault KDF parameters, not signature size, dominate user-visible latency on this machine. (2) Base64 JSON inflates the signature payload by about a third, which matters more for the wire size than the algorithm choice. (3) Database growth per credential (2.5 to 4.5 KB) is quantized by 4 KB SQLite pages and should be re-measured with PostgreSQL.

**Linux Release build (2026-11-10).** `docs/evaluation/bench-2026-11-10-linux.json`: same harness and 20 iterations, run in CI on a GitHub Actions `ubuntu-latest` VM (the run log shows image `ubuntu-26.04`; CI is now pinned to it) with liboqs 0.16.0 built by GCC in Release mode.

| Variant | keygen / sign / verify (median ms) | login end to end (median ms) | signer incl. vault unlock (median ms) |
|---|---|---|---|
| ML-DSA-44 | 0.046 / 0.084 / 0.045 | 163 | 150 |
| ML-DSA-65 | 0.069 / 0.168 / 0.065 | 163 | 150 |
| ML-DSA-87 | 0.104 / 0.186 / 0.098 | 164 | 151 |

Signing is 20 to 30 times faster than the Windows Debug numbers, and login is about half. The machines differ, so this mixes build type with hardware and is not a controlled comparison. Finding (1) holds and is stronger: ML-DSA is under 0.2 ms of a 163 ms login, so the vault KDF is about 92% of it. Wire sizes and database bytes match the Windows run.

## Prior art (searched 2026-11-06; limited, not a literature review)

- Mitra and Sethuraman, *The Qey: Implementation and performance study of post quantum cryptography in FIDO2*, arXiv:2510.21353 (2025).
- Mitra et al., *ML-DSA for Web Authentication*, IETF Internet-Draft draft-vitap-ml-dsa-webauthn-04.
- Software HSM "policy enforcement point" ideas exist in IETF drafts (for example draft-xzinn-softhsm-enforcement-rules); a full comparison is outstanding.

ML-DSA in FIDO2/WebAuthn is therefore **not** a novelty claim. The three contributions above were not found in these sources, but absence from a short search is not evidence of novelty. Before using the word "novel", search CTAP/FIDO credential-migration and authenticator-policy literature, read the papers above in full, and compare against Apple/Google passkey sync and FIDO's credential exchange work.

## Known limitations

- The virtual token is a process boundary, not tamper-resistant hardware, and keeps keys only in memory. `cli migrate` therefore migrates into a token that disappears when the command ends; use it to demonstrate the flow, not to keep an account.
- No credential revocation endpoint, session store, TLS, rate limiting on the server, account recovery, or user authentication for first registration of a username.
- Server-side policy checks cover relying party, operations and expiry only.
- Developed on Windows x64 with a Debug-configured liboqs 0.16.0 build that prints a constant-time warning. CI runs the suite on Linux with a Release build and PostgreSQL 17, and that log contains no such warning; absence of the warning is not a constant-time verification. macOS is untested; benchmarks are small (20 iterations on a shared CI VM) and not release numbers.
- The protocol is a custom, WebAuthn-inspired design, not WebAuthn/CTAP compatible. Its message encoding and migration protocol have had no formal analysis or independent review.

## Ideas to explore next (your choice)

1. **Formal model.** Model the canonical message, challenge lifecycle and migration in Tamarin or ProVerif and prove no cross-operation or cross-relying-party replay. This is the strongest way to turn the candidate contributions into a defensible result.
2. **Real token.** Port the framed protocol to a Raspberry Pi Pico or STM32 using a vetted embedded ML-DSA implementation (PQClean or pqm4); measure peak RAM and signing latency (experiment E-06).
3. **Recovery credential.** A cold backup credential whose policy allows only `migrate`, so a lost device is recovered by migration rather than re-enrollment.
4. **Server-required minimum policy.** The relying party refuses credentials whose policy is weaker than its own (for example a rate cap above N), making policy a verifiable enrollment attribute.
5. **Split authorization.** Require both a software and a token signature for sensitive operations (2-of-2).
6. **Hybrid signatures.** Add an Ed25519 signature next to ML-DSA in the canonical message and measure the cost.
7. **Credential transparency log.** An append-only hash chain of registrations, migrations and revocations so users can detect a substituted credential.
8. **WebAuthn bridge.** Map credentials to the COSE identifiers requested by the IETF draft and test against a WebAuthn test harness.
9. **Vault KDF tuning.** Since the KDF dominates latency, measure Argon2id parameters against a target unlock time and unlock caching with explicit timeouts.
10. **Controlled benchmark.** The Linux Release run (2026-11-10) used different hardware from the Windows run; benchmark both build types on one machine to separate the build effect from the hardware effect.
