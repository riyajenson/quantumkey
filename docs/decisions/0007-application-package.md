# ADR 0007: Application code lives in the `quantumkey` package

**Status:** Accepted. Follows [phase2 ADR 0001](../../phase2/decisions/0001-validation-boundary.md).
**Date:** 2026-11-06

## Decision

Phase 3 and later code lives in `quantumkey/` (`protocol`, `server`, `authenticator`, `crypto.py`, `bench.py`) with tests in `tests/`. `phase2/` stays unchanged as the record of the technology validation, and its tests still run.

## Rationale

ADR 0001 required Phase 2 code to stay disposable and separate from the real protocol. The new package reuses the validated choices (liboqs, FastAPI, SQLAlchemy, Argon2id, AES-GCM) but not the Phase 2 code, whose API had no challenges and whose vault was single-credential (format v1).

## Consequences

`phase2/vault.py`, `phase2/signing_backend.py` and `phase2/validation_service.py` are superseded and must not be extended. Once the team no longer needs the Phase 2 evidence to run, `phase2/` can be reduced to its documents.
