# QuantumKey Milestone Acceptance

**Status:** 2026-11-06. Phase numbering follows [`PHASES.md`](../PHASES.md) (8 phases). This file replaces the earlier `PHASE1_STATUS.md` tracker.

## Phase 1: Research, requirements, threat model. **Met with gaps**

Gate: *the team can explain what QuantumKey protects, what it does not, how registration and login behave, and which assumptions need experimental proof.*

- [x] Terminology and boundaries: `docs/TERMINOLOGY_AND_BOUNDARIES.md`
- [x] Requirements and non-goals: `docs/REQUIREMENTS.md`
- [x] Protocol and API contracts: `docs/API_CONTRACTS.md`
- [x] ML-DSA/liboqs feasibility: `docs/CRYPTO_FEASIBILITY.md`, `phase-1/02-crypto-hardware-riya/`
- [x] Vault and credential lifecycle: `docs/VAULT_SPECIFICATION.md`
- [x] Threat model and risk register: `docs/THREAT_MODEL.md`
- [x] Experiment plan: `docs/EXPERIMENT_PLAN.md`
- [x] Acceptance criteria: this file
- [x] Workstream folders 01, 03, 04 and 05 under `phase-1/` index the consolidated docs; risk register, test strategy and blockers added
- [ ] Formal guide sign-off (checklist ready: `docs/PHASE_1_3_SIGNOFF.md`)

## Phase 2: Architecture and technical validation. **Met with limitations**

- [x] Reproducible ML-DSA validation on Windows (`phase2/VALIDATION_RESULTS.md`)
- [x] FastAPI/SQLAlchemy/SQLite/PostgreSQL validation
- [x] Vault proof of concept
- [x] Draft signing-backend contract (superseded by the structured `Signer`, ADR 0005)
- [x] Architecture decision records (`phase2/decisions/`, `docs/decisions/`)
- [x] Non-Windows reproducibility and an optimized build: CI on Linux with liboqs in Release mode passes the suite and produced `docs/evaluation/bench-2026-11-10-linux.json` (2026-11-10)
- [x] Local Docker reproduction: the image builds behind Norton's TLS inspection and passes the suite on SQLite and PostgreSQL 17 (2026-11-10, `docs/BLOCKERS.md` B-04)

## Phase 3: Protocol and backend foundation. **Met**

Gate: challenge generation and consumption pass expiry, replay, mismatch and concurrency tests. All pass in `tests/server/test_challenge_lifecycle.py` on SQLite and PostgreSQL 17 (13 tests, including 8 concurrent completions with exactly one success). Alembic migration, its model-match test and the CI workflow are in place, and CI passed on PR #4 (run 42782171367, 2026-11-10).

## Phase 4: End-to-end authentication. **Met**

Gate: valid registration and login succeed repeatedly, and altered signatures, altered messages, expired or reused challenges and mismatched credentials consistently fail. Covered for all three variants by `tests/e2e/test_software_flow.py` and the server tests, and demonstrated live with the CLI.

## Phase 5: Secure authenticator vault. **Met**

Gate: no plaintext PIN or private key on disk, wrong PINs fail safely, modified ciphertext is detected. Met (vault tests). Also done: multiple credentials, PIN-checked deletion that overwrites the row (`cli delete`), PIN change and KDF-parameter upgrade (`cli change-pin`), opt-in unlocked sessions with a fixed lifetime and `lock()`, and vault format v3 with in-place migration from v2 (`tests/authenticator/`). Device identity: each vault and virtual token has a random id, sent at registration and migration and stored with the credential (self-reported, not attested; `tests/authenticator/test_device_identity.py`).

## Phase 6: Hardening, observability, reproducibility. **Started**

Done: benchmark harness, Windows Debug and Linux Release results, and a CI workflow that runs the tests on SQLite and PostgreSQL and the benchmark on every PR. The Docker image builds and passes the suite locally (BLOCKERS B-04). Rate limiting, a request-size cap and purging of expired rows are in (R-10). Still open: load tests, audit events, a clean-machine reproduction.

## Phase 7: Desktop GUI. **Not started** (deliberately deferred)

## Phase 8: Hardware migration. **Partially met in simulation**

Gate: software and hardware backends pass the same signing-contract tests, and the server authenticates without knowing which produced the signature. Met for the software signer and the **virtual token** (`tests/e2e/test_migration.py`). Not met for real hardware.

## Merge checklist (per `PHASES.md`)

Before merging into `main`: review the docs against the code, confirm no secrets are committed (`git log -p` contains no key bytes; `.gitignore` covers `*.sqlite3`), run `python -m pytest -q`, and get team approval.
