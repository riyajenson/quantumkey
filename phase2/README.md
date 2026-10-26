# Phase 2: Architecture and Technical Validation

This phase validates the highest-risk technology assumptions with isolated experiments. The files here are research prototypes, not production authentication or vault components.

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
6. Confirm modified messages fail verification and private-key bytes are absent from the vault file and API response.

The service and vault are intentionally minimal. They do not implement the Phase 3 protocol, challenge expiry, replay protection, authentication, or production schema/migrations.

The SQLite API/database experiment is complete. The Phase 2 PostgreSQL validation gate remains open because the installed Docker client cannot reach its `desktop-linux` daemon, and no local PostgreSQL service or client is installed. Before selecting PostgreSQL, rerun the HTTP E2E flow against PostgreSQL and verify transaction rollback/commit, binary key round-trip, duplicate-key conflict handling, and persistence after a service restart.

Run the whole E2E suite from the repository root:

```powershell
python -m pytest -q
```

The separate 100-iteration cryptography benchmark is described in [Validation results](VALIDATION_RESULTS.md).
