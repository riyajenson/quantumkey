# ADR 0004: Length-prefixed canonical signed message

**Status:** Accepted for protocol v1
**Date:** 2026-11-06

## Decision

Every signature covers `"QuantumKey/v1" 0x00 | operation byte | 7 length-prefixed fields` (rp_id, transaction_id, challenge, credential_id, algorithm, policy_hash, extra), implemented in `quantumkey/protocol/message.py`. The relying party rebuilds the message from its own records. ML-DSA's FIPS 204 context string is not used.

## Rationale

A fixed binary layout with 4-byte lengths has exactly one encoding per message, so there are no JSON/CBOR canonicalization questions. Placing the domain tag and operation first separates registration, login and migration signatures, and including the algorithm and policy hash prevents downgrade and policy swaps. Keeping domain separation inside the message makes it independent of whether a given ML-DSA implementation supports context strings, which matters for a future embedded token.

## Consequences

The format is not WebAuthn's `authenticatorData || clientDataHash`. Changing it requires a new domain tag (`QuantumKey/v2`). Using the FIPS 204 context string *in addition* remains an open option that needs testing against liboqs-python 0.16.
