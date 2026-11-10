# QuantumKey Risk Register

**Status:** 2026-11-06. Likelihood and impact are L/M/H judgements for a research prototype, not measurements. Review this file at every phase gate.

| ID | Risk | L | I | Mitigation | Status |
|---|---|---|---|---|---|
| R-01 | Software signer gives no protection against a compromised host | H | H | Virtual token enforces policy in a separate process; real hardware token (Phase 8) | Open, documented |
| R-02 | First registration is unauthenticated, so anyone can claim an unused username | H | H | Invite token or login-gated enrollment | Open |
| R-03 | Windows MSVC Debug build triggers a liboqs timing-safety warning | M | M | Linux GCC Release build in CI shows no warning (2026-11-10); report numbers from that build. The warning's absence is not a constant-time verification, and local development still uses the Debug build | Mitigated |
| R-04 | No formal analysis of the signed-message and migration protocol | M | H | Tamarin or ProVerif model; until then no security claim beyond tests | Open |
| R-05 | Novelty claims are unproven; prior-art search was brief | M | H | Structured literature pass before any "novel" claim in the report | Open |
| R-06 | liboqs or liboqs-python API/version drift breaks the build | M | M | Versions pinned in `phase2/requirements.lock.txt`, `Dockerfile` and CI | Mitigated |
| R-07 | Challenge replay or race lets one challenge succeed twice | L | H | Atomic conditional UPDATE; 8-thread test on SQLite and PostgreSQL | Mitigated |
| R-08 | Schema changes corrupt or fork deployed databases | M | M | Alembic migration plus a test that it matches the models | Mitigated |
| R-09 | Argon2id unlock dominates login latency (~256 ms of ~325 ms) | H | L | Calibrate to a target unlock time; report trade-off (E-04) | Open |
| R-10 | Server has no rate limiting, so challenge flooding fills the table | M | M | Per-IP and per-user limits; expired-challenge cleanup | Open |
| R-11 | Hostile inputs crash the parser or token | L | M | Strict parsers, size limits, type-confusion tests; fuzzing still open | Partly mitigated |
| R-12 | Team capacity: one person does all workstreams | H | M | Keep scope to the prototype; phases gated by tests and docs, not headcount | Accepted |
| R-13 | PostgreSQL and TLS behaviour in a real deployment untested | M | M | PostgreSQL covered in tests; TLS excluded from scope and documented | Partly mitigated |
| R-14 | Lost PIN or vault means lost credential with no recovery | M | M | Re-enroll through the relying party; recovery flow not designed | Open |
