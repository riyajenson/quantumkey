# ADR 0005: Structured-request signing contract

**Status:** Accepted. Supersedes [phase2 ADR 0002](../../phase2/decisions/0002-signing-backend-contract.md).
**Date:** 2026-11-06

## Decision

Signers implement `create_credential`, `public_credential` and `sign(credential_id, SignRequest)` (`quantumkey/authenticator/core.py`). A `SignRequest` carries the operation, RP, transaction, challenge and (for migration only) the target credential. There is no method that signs caller-supplied bytes and none that exports a private key. Keys are addressed by credential id. A shared `SigningCore` enforces the credential's policy and builds the canonical message, both in the software signer and inside the virtual token.

## Rationale

ADR 0002 passed raw private-key bytes and raw messages between layers and left opaque handles as a follow-up. With a raw-bytes signer, a malicious host can obtain a signature over any message. With structured requests, the most it can obtain is a signature the policy already allows (threat T-08). One core for both backends means the software and token signers pass the same contract tests, which is the Phase 8 gate.

## Consequences

Adding a new operation means changing the core and the token protocol together. The software signer still decrypts the key in the host process, so its policy checks are advisory against host malware. Device status, cancellation, timing reports and key deletion are not yet in the contract.
