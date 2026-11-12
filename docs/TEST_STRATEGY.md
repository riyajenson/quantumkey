# QuantumKey Test Strategy

**Status:** 2026-11-06.

## Levels

| Level | What it proves | Where |
|---|---|---|
| Unit | Message encoding, policy checks, vault crypto, parsers | `tests/protocol`, `phase2/tests` |
| Hardening | Type confusion, oversized fields, duplicate and malformed input | `tests/protocol/test_hardening.py` |
| Server lifecycle | Expiry, replay, mismatch, tampering, concurrency | `tests/server/test_challenge_lifecycle.py` |
| Schema | Alembic migration matches the models; downgrade is clean | `tests/server/test_migrations.py` |
| End to end | Register, login, migrate for all three ML-DSA variants, software and token | `tests/e2e` |
| Cross-database | The server suite runs on SQLite and PostgreSQL 17 | `scripts/run_server_tests_postgres.sh`, CI |
| Cross-platform | Windows (Debug) and Linux (Release) | `Dockerfile`, CI |
| Performance | Latency, sizes, storage per variant | `python -m quantumkey.bench`, `docs/evaluation/` |

## Rules

- Every security property in `THREAT_MODEL.md` marked "mitigated" must point to a test.
- A failed attempt must fail closed: the challenge is burned and the response gives no detail beyond the error code.
- Fixtures use a fake clock; nothing sleeps for expiry.
- Tests never touch a real database: PostgreSQL is accepted only on loopback with a database named `qk_test_*`.
- Secrets never appear in logs or test output; PINs are test constants only.

## Test infrastructure

- `tests/helpers.py` provides the minimal protocol client, the fake clock and `database_url()`.
- CI (`.github/workflows/ci.yml`) builds liboqs 0.16.0 in Release mode, then runs the whole suite on SQLite and the server suite on PostgreSQL.

## Not yet covered

Coverage-guided fuzzing (seeded random and mutation fuzzing is in `tests/protocol/test_fuzz.py`); load tests; cross-checking ML-DSA key generation and signing against a second implementation (verification is checked against NIST's ACVP vectors, E-03); formal protocol analysis.

**PostgreSQL runs (2026-11-12).** `tests/conftest.py` closes every relying-party database engine after each test, so the server suite no longer exhausts PostgreSQL's connections (it did once it passed about 75 tests), and the Phase 2 end-to-end test empties the database before each of its runs. The whole suite (303 tests) passes against PostgreSQL 17 three times in a row on one database, leaving no connections open. CI still runs only `tests/server` against PostgreSQL.
