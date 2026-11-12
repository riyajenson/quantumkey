# Cryptographic Feasibility

**Status:** Answered for desktop software; open for hardware. Detailed evidence lives in `phase-1/02-crypto-hardware-riya/` and `phase2/VALIDATION_RESULTS.md`.

## 1. Decisions

| Item | Decision | Confidence |
|---|---|---|
| Signature scheme | ML-DSA (FIPS 204), standardized names only | High |
| Default parameter set | ML-DSA-65; 44 and 87 retained | Provisional |
| Library | liboqs 0.16.0 via liboqs-python 0.16.0.1, pinned | Functional validation passed |
| Private-key form | liboqs expanded secret key (2,560 / 4,032 / 4,896 B), sealed in the vault | Measured |
| Context string | Not used; domain separation in the canonical message | Decision (ADR 0004) |
| Vault KDF / AEAD | Argon2id (t=3, 64 MiB) / AES-256-GCM | Provisional, needs calibration |

## 2. Evidence by dimension

| Dimension | Finding |
|---|---|
| Key and signature size | Match FIPS 204 Table 2 exactly for all variants |
| Primitive latency | 0.5–4.4 ms median for keygen, sign and verify (Windows Debug build); 0.05–0.19 ms (Linux GCC Release build in CI, different hardware) |
| End-to-end login | About 325 ms median, dominated by Argon2id (about 256 ms) |
| Transport | 3.7–6.6 KB JSON per login; base64 adds about 33% |
| Storage | 2.5–4.5 KB per credential row on the server (SQLite page-quantized) |
| Interoperability | Verification agrees with all 45 NIST ACVP ML-DSA sigVer vectors (pure, with context). Key generation and signing are not cross-checked |
| Side channels | MSVC Debug build warns that constant time is not guaranteed; the Linux GCC Release build in CI shows no such warning. No constant-time verification has been done. Open |
| Embedded | Analysed, not measured (`hardware-constraints.md`) |
| Maintenance | liboqs is actively maintained. OQS describes it as a research/prototyping library |

## 3. Open questions

- How much of the Linux speed-up is the Release build and how much the hardware? (Measure both builds on one machine.)
- Peak RAM on an MCU-class target with a portable ML-DSA implementation?
- Should FIPS 204 context strings be used, and does liboqs-python 0.16 implement them correctly?
- Do independent ML-DSA implementations (for example PQClean or the Go/Rust stacks) verify QuantumKey signatures, and do seeded key generations match NIST's keyGen vectors?
