# ADR 0003: Phase 2 technology findings

**Status:** Provisional
**Date:** 2026-10-26

## Decision

Retain FastAPI and SQLAlchemy for the planned backend and Argon2id with AES-GCM for the local vault proof of concept. Use SQLite for the local vault and retain PostgreSQL for the server-side prototype; both database paths passed the Phase 2 E2E flow. Keep ML-DSA-65 as a provisional software default while retaining ML-DSA-44 and ML-DSA-87 for comparisons.

## Evidence

The three variants passed three 100-iteration keygen/sign/verify runs and the HTTP E2E flow against SQLite and PostgreSQL 17.11. The vault survived persistence and reopen, rejected a wrong PIN, detected modified algorithm metadata, and did not contain the plaintext private key. Binary public-key storage round-tripped through SQLAlchemy on both databases; PostgreSQL duplicate registration rolled back and preserved the existing record, which remained verifiable after restarting the API process.

## Limitations

The MSVC build emitted liboqs's constant-time optimization-barrier warning, and performance numbers came from a Debug build. Non-Windows environments, migrations, and concurrency were not validated. The benchmark must be rerun with an approved constant-time toolchain and an optimized build before final parameter selection or security claims.
