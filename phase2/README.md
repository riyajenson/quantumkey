# Phase 2: Architecture and Technical Validation

This phase validates the highest-risk technology assumptions with isolated experiments. The files here are research prototypes, not production authentication or vault components.

> **Superseded code (2026-11-06):** the application now lives in [`quantumkey/`](../quantumkey). `vault.py`, `signing_backend.py` and `validation_service.py` remain only as validation evidence; see [ADR 0007](../docs/decisions/0007-application-package.md).

## Results

- [Validation results](VALIDATION_RESULTS.md) records the Windows ML-DSA benchmark and the API/database/vault E2E result, including limitations.
- [Development environment](DEVELOPMENT.md) gives the pinned setup and rerun commands.
- [Signing backend contract](signing_backend.py) is the draft interface used by the experiment.
- [Architecture decisions](decisions/) records current decisions and open questions.

## E2E validation

The HTTP E2E scenario starts a separate FastAPI process and exercises an authenticator-to-service flow for each ML-DSA variant:

1. Generate a keypair through liboqs.
2. Save the private key in the local SQLite vault encrypted with an Argon2id-derived key and AES-GCM.
3. Reopen the vault, unlock the private key, and confirm wrong PINs and modified algorithm metadata fail.
4. Send only the public key to the FastAPI service and persist it as a SQLAlchemy binary field in SQLite.
5. Sign a message with the unlocked private key and have the service verify it using the database-loaded public key.
6. Confirm duplicate registration rolls back without replacing the stored key, restart the API, and verify that the record and signature still work.
7. Confirm modified messages fail verification and private-key bytes are absent from the vault file and API response.

The service and vault are intentionally minimal. They do not implement the Phase 3 protocol, challenge expiry, replay protection, authentication, or production schema/migrations.

The HTTP E2E flow passed against both SQLite and PostgreSQL 17.11. The PostgreSQL run also covered transaction commit and duplicate-key rollback using a different public key, binary key round-trip, and persistence after a service restart. Regular `pytest` runs always use isolated SQLite files and ignore ambient `QK_DATABASE_URL`; PostgreSQL requires an explicit loopback `QK_TEST_DATABASE_URL` whose database name begins with `qk_test_`. Run it with [the PostgreSQL E2E script](run_postgres_e2e.ps1); the script starts a temporary container using a pinned image digest and stops only that container afterward.

Run the whole E2E suite from the repository root:

```powershell
python -m pytest -q
```

The separate 100-iteration cryptography benchmark is described in [Validation results](VALIDATION_RESULTS.md).
