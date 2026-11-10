# QuantumKey Blockers and Open Limitations

**Status:** 2026-11-06. Items leave this file only when the evidence is committed.

| ID | Item | Blocks | Next step |
|---|---|---|---|
| B-01 | No hardware token; the virtual token is a process boundary only | Any hardware-isolation claim | Phase 8 MCU port (E-06) |
| B-02 | **Resolved 2026-11-10.** First registration requires an operator-issued, single-use invite (FR-15, R-02). Account-takeover resistance still depends on delivering the invite over a trusted channel | — | Rate limiting (R-10) for defence in depth |
| B-03 | No formal protocol analysis | Any claim of proven security | Tamarin/ProVerif model |
| B-04 | **Resolved 2026-11-10.** CI (run 42782171367) built liboqs in Release mode on Linux, passed the suite on SQLite and PostgreSQL 17, and produced `docs/evaluation/bench-2026-11-10-linux.json`. The local Docker build failed because Norton Web Shield re-signs HTTPS; the `Dockerfile` now accepts the inspecting root certificate as an optional build secret (`extra_ca`), used only by the download steps and not stored in the image. The image then also needed `libssl-dev`. Locally in Docker: 68 tests pass, and the 16 server tests pass on PostgreSQL 17 | — | Keep certificate checks on. CI builds the image and runs the suite in it |
| B-05 | Prior-art search incomplete | Calling any contribution novel | Literature pass on structured-request signing and key-export-free migration |
| B-06 | No second-implementation cross-check of ML-DSA | Interoperability claims | E-03 |
