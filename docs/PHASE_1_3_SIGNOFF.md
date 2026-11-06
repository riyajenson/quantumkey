# Phases 1-3 Sign-off Checklist

**Status:** 2026-11-06. Every output named in [`PHASES.md`](../PHASES.md) for Phases 1-3, with its evidence. "Sign-off" lines are for the reviewer to initial and date.

## Phase 1: Research, requirements, threat model

| Output | Evidence |
|---|---|
| Agreed terminology and system boundaries | `docs/TERMINOLOGY_AND_BOUNDARIES.md` |
| Requirements and non-goals | `docs/REQUIREMENTS.md` |
| Preliminary protocol and API contracts | `docs/API_CONTRACTS.md`, ADRs 0004-0006 |
| ML-DSA/liboqs feasibility results | `docs/CRYPTO_FEASIBILITY.md`, `phase-1/02-crypto-hardware-riya/` |
| Vault and credential-lifecycle specification | `docs/VAULT_SPECIFICATION.md` |
| Threat model and risk register | `docs/THREAT_MODEL.md`, `docs/RISK_REGISTER.md` |
| Research metrics and experiment plan | `docs/EXPERIMENT_PLAN.md`, `docs/TEST_STRATEGY.md` |
| Acceptance criteria for the first milestone | `docs/MILESTONE_ACCEPTANCE.md` |

Gate: the claims and non-claims are stated in `TERMINOLOGY_AND_BOUNDARIES.md` and `THREAT_MODEL.md`; assumptions still needing proof are in `docs/BLOCKERS.md`.

Sign-off: ______________  Date: ________

## Phase 2: Architecture and technical validation

| Output | Evidence |
|---|---|
| Standalone ML-DSA validation results | `phase2/VALIDATION_RESULTS.md`, `phase-1/.../experiments/results.md` |
| Database and API technology validation | `phase2/VALIDATION_RESULTS.md` (SQLite and PostgreSQL 17) |
| Vault encryption proof of concept | `phase2/vault.py`, superseded by `quantumkey/authenticator/vault.py` |
| Draft `SigningBackend` interface | `phase2/signing_backend.py`, superseded by the `Signer` protocol (ADR 0005) |
| Architecture decision records | `phase2/decisions/`, `docs/decisions/` |
| Development-environment instructions | `phase2/DEVELOPMENT.md`, `Dockerfile`, `.github/workflows/ci.yml` |

Gate: libraries work reproducibly on Windows and Linux (see the Linux result in `docs/evaluation/`), or limitations are documented in `docs/BLOCKERS.md`.

Sign-off: ______________  Date: ________

## Phase 3: Protocol and backend foundation

| Output | Evidence |
|---|---|
| User, Credential, Challenge models | `quantumkey/server/models.py` |
| Registration start/complete APIs | `quantumkey/server/app.py`, `tests/e2e` |
| Login start/complete APIs | `quantumkey/server/app.py`, `tests/e2e` |
| Expiring, single-use challenges | `RelyingParty._consume`, `tests/server/test_challenge_lifecycle.py` |
| Versioned canonical message specification | `docs/decisions/0004-canonical-message.md`, `quantumkey/protocol/message.py` |
| Migration and test infrastructure | `migrations/`, `tests/server/test_migrations.py`, `tests/helpers.py`, `.github/workflows/ci.yml` |

Gate: expiry, replay, mismatch and concurrency tests pass on SQLite and PostgreSQL 17 (`scripts/run_server_tests_postgres.sh`).

Sign-off: ______________  Date: ________
