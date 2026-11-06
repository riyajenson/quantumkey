# Policy-Bound, Migratable Post-Quantum Credentials — Design

**Status:** Approved by project owner (2026-11-06, "go ahead"). Design calls marked *(call)* were made by the builder and may be revised.

## Intent

Take QuantumKey from the Phase 2 technology spike to a working prototype of the Phase 4 milestone (ML-DSA keygen → server challenge → authenticator signing → server verification, with replay/expiry/tamper failures rejected) and add a research contribution on top.

## Prior art (checked 2026-11-06; limited search, not exhaustive)

- Mitra & Sethuraman, *The Qey: Implementation and performance study of post quantum cryptography in FIDO2*, arXiv:2510.21353 (Oct 2025): ML-DSA in FIDO2, performance study.
- Mitra et al., *ML-DSA for Web Authentication*, IETF Internet-Draft `draft-vitap-ml-dsa-webauthn-04`: COSE identifiers (-48/-49/-50 requested), encodings, ES256/RS256 fallback, AES-256-GCM storage guidance.

Consequence: "ML-DSA passkeys" is **not** a novelty claim. The contribution below is narrower and must be described as *candidate*, pending a deeper literature review.

## Contribution (candidate)

1. **Structured-request signing.** The authenticator/token never signs host-supplied bytes. The host sends structured fields (operation, RP, transaction, challenge, credential, algorithm); the signer builds the canonical message *inside the boundary*, after checking a credential-bound policy. This removes the chosen-message signing-oracle class (threat T-08) by construction, and the contract is identical for software and hardware backends.
2. **Credential-bound signing policy.** A canonical policy (allowed operations, RP binding, expiry, rate limit) is hashed and bound into the registration message, so the server and signer agree on it and it cannot be swapped later.
3. **Key-export-free migration.** A software credential authorizes a fresh credential created in another backend (the "virtual token") via a dual-signed migration statement; the server atomically activates the new credential and revokes the old one. The private key never moves.
4. **Evaluation.** End-to-end protocol cost (payload bytes, DB growth, latency/throughput) for ML-DSA-44/65/87.

## Goals / non-goals / anti-goals

- Goals: working server + CLI authenticator + virtual token; all negative cases rejected; reproducible tests.
- Non-goals: WebAuthn/CTAP compliance, browser integration, real hardware, GUI, production hardening.
- Anti-goals: claiming "quantum-proof", claiming novelty beyond the above, claiming hardware security for the virtual token (it is a process boundary, not a tamper-resistant device).

## Approaches considered

A. Extend `phase2/` in place — fast, but mixes disposable code with the real thing. Rejected.
B. New `quantumkey/` package (server, authenticator, protocol), reuse validated vault/backend logic — **chosen**.
C. Full WebAuthn/CBOR compatibility layer — out of scope; Qey/IETF already occupy that space.

## Design

Layout *(call)*: `quantumkey/protocol` (canonical message, policy), `quantumkey/server`, `quantumkey/authenticator` (backends, vault, CLI), `tests/`.

Canonical message *(call)*: `b"QuantumKey/v1\x00"` domain tag, 1-byte operation (1 register, 2 login, 3 migrate), then fixed-order fields each as 4-byte big-endian length + bytes: rp_id, transaction_id, challenge, credential_id, algorithm, policy_hash, extra. No JSON/CBOR ambiguity; strict parser rejects trailing bytes. ML-DSA context string not used (domain separation lives in the message).

Policy *(call)*: JSON with sorted keys, no whitespace; fields `allowed_ops`, `rp_id`, `not_after` (unix seconds), `max_signs_per_minute`. `policy_hash` = SHA-256 of canonical bytes.

Server: FastAPI + SQLAlchemy. Tables users, credentials (status active/revoked, policy blob+hash, replaced_by), challenges (purpose, expires_at, used_at). Challenge consumption is a single conditional UPDATE (atomic). TTL 60 s *(call)*. Endpoints: `/auth/register/{start,complete}`, `/auth/login/{start,complete}`, `/auth/migrate/{start,complete}`, `/auth/credentials/{id}/revoke`. The server reconstructs the canonical message itself; it never trusts a client-supplied message.

Signer contract: `generate(alg) -> (handle, public_key)`; `sign(handle, SignRequest) -> signature`, where SignRequest is structured and policy is enforced before signing. Implementations: in-process software signer (vault-backed) and a subprocess "virtual token" speaking length-framed JSON over stdio.

Vault *(call)*: reuse the Phase 2 Argon2id + AES-256-GCM scheme; add multiple credentials, policy stored as authenticated data.

## Phases

3. Protocol and server foundation (canonical message, policy, models, endpoints, challenge tests).
4. End-to-end milestone (authenticator CLI + software signer; replay/expiry/tamper/mismatch tests).
5. Vault and policy engine (multi-credential, policy enforcement, structured-request signing).
6. Evaluation (benchmarks, sizes, DB growth) and prior-art note update.
7. Virtual token and migration protocol.

## Left to the builder

Exact error codes, CLI ergonomics, benchmark harness details.
