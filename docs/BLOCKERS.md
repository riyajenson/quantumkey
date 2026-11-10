# QuantumKey Blockers and Open Limitations

**Status:** 2026-11-06. Items leave this file only when the evidence is committed.

| ID | Item | Blocks | Next step |
|---|---|---|---|
| B-01 | No hardware token; the virtual token is a process boundary only | Any hardware-isolation claim | Phase 8 MCU port (E-06) |
| B-02 | Unauthenticated first registration | Any claim about account takeover resistance | Design and add enrollment control |
| B-03 | No formal protocol analysis | Any claim of proven security | Tamarin/ProVerif model |
| B-04 | **Partly resolved 2026-11-10.** CI (run 42782171367) built liboqs in Release mode on Linux, passed the suite on SQLite and PostgreSQL 17, and produced `docs/evaluation/bench-2026-11-10-linux.json`. Still open: a local Linux Docker build fails because this machine's network re-signs HTTPS (host sets `NODE_EXTRA_CA_CERTS`), so the container cannot verify `github.com`, and the `Dockerfile` is therefore untested | A clean-machine reproduction via Docker (Phase 6 gate) | Add the proxy root CA to the image, or build on a network without interception. Do not disable certificate checks |
| B-05 | Prior-art search incomplete | Calling any contribution novel | Literature pass on structured-request signing and key-export-free migration |
| B-06 | No second-implementation cross-check of ML-DSA | Interoperability claims | E-03 |
