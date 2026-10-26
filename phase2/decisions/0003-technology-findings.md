# ADR 0003: Phase 2 technology findings

**Status:** Provisional
**Date:** 2026-10-26

## Decision

Retain FastAPI and SQLAlchemy for the planned backend and Argon2id with AES-GCM for the local vault proof of concept. Continue to evaluate SQLite for local vault storage. Keep ML-DSA-65 as a provisional software default while retaining ML-DSA-44 and ML-DSA-87 for comparisons.

## Evidence

The three variants passed the 100-iteration keygen/sign/verify experiment and the HTTP E2E flow. The vault survived persistence and reopen, rejected a wrong PIN, detected modified algorithm metadata, and did not contain the plaintext private key. Binary public-key storage round-tripped through SQLAlchemy/SQLite.

## Limitations

The MSVC build emitted liboqs's constant-time optimization-barrier warning, and performance numbers came from a Debug build. PostgreSQL and non-Windows environments were not validated. The benchmark must be rerun with an approved constant-time toolchain and an optimized build before final parameter selection or security claims.
