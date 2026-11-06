# QuantumKey Blockers and Open Limitations

**Status:** 2026-11-06. Items leave this file only when the evidence is committed.

| ID | Item | Blocks | Next step |
|---|---|---|---|
| B-01 | No hardware token; the virtual token is a process boundary only | Any hardware-isolation claim | Phase 8 MCU port (E-06) |
| B-02 | Unauthenticated first registration | Any claim about account takeover resistance | Design and add enrollment control |
| B-03 | No formal protocol analysis | Any claim of proven security | Tamarin/ProVerif model |
| B-04 | Benchmarks come from a Windows Debug build. A local Linux Docker build fails: this machine's network re-signs HTTPS (host sets `NODE_EXTRA_CA_CERTS`), so the container cannot verify `github.com` | Publishable performance numbers | Run the same suite and `python -m quantumkey.bench` on the GitHub Actions Linux runner (CI builds liboqs in Release mode), or add the proxy root CA to the image. Do not disable certificate checks. The `Dockerfile` is untested for this reason |
| B-05 | Prior-art search incomplete | Calling any contribution novel | Literature pass on structured-request signing and key-export-free migration |
| B-06 | No second-implementation cross-check of ML-DSA | Interoperability claims | E-03 |
