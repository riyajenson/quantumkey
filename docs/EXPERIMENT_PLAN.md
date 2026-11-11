# QuantumKey Experiment Plan

**Status:** Updated 2026-11-06 with what has run. Each experiment records machine, OS, versions, build, commit and iteration count with its results.

## 1. Experiments

| ID | Question | Status | Where |
|---|---|---|---|
| E-01 | ML-DSA keygen/sign/verify feasibility on desktop | **Done** (3 x 100 iterations) | `phase-1/.../experiments/results.md` |
| E-02 | Does the registration/login state machine meet the contract? | **Done** (automated) | `tests/server`, `tests/e2e` |
| E-03 | Do independent ML-DSA implementations agree? | **Partial** (2026-11-12): liboqs verification matches all 45 NIST ACVP sigVer vectors (pure, with context) for all three parameter sets, and `crypto.verify` rejects context-bound signatures. Key generation and signing are not cross-checked: liboqs-python has no seeded keygen and signs randomized | `tests/protocol/test_acvp.py`, `tests/data/acvp/` |
| E-04 | Vault usability: unlock latency, overhead, corruption | **Partial**: latency and tamper detection measured; calibration tool and session measurement built and run in CI; results to record | `python -m quantumkey.authenticator.calibrate`, `python -m quantumkey.bench` | `docs/evaluation/`, vault tests |
| E-05 | Payload sizes and transport overhead | **Done** for JSON/HTTP | `docs/evaluation/bench-2026-11-06.json` |
| E-06 | MCU feasibility (RAM, flash, latency) | Open (analysis only) | `hardware-constraints.md` |
| E-07 | Can a token enforce allowed signing requests? | **Done** for the virtual token | `tests/e2e/test_migration.py` |
| E-08 | FPGA benefit | Deferred until E-06 shows a bottleneck | — |
| E-09 | Robustness against hostile inputs | **Partial**: strict-parser tests; fuzzing open | protocol and token tests |
| E-10 | Migration correctness (software to token, cross-variant) | **Done** | `tests/e2e/test_migration.py` |
| E-11 | End-to-end protocol cost per variant | **Done** on Windows Debug and Linux Release (20 iterations each) | `python -m quantumkey.bench`, `docs/evaluation/` |

## 2. Method

- Record platform, Python, CPU, liboqs version and build type with every result (the benchmark prints these).
- Report median, mean and p95. Keep run-to-run ranges rather than a single number.
- Measure end to end as well as primitives. Never claim security from performance numbers.
- Keep raw JSON under `docs/evaluation/` named by date.

## 3. Next experiments, in order

1. ~~Re-run E-11 on Linux with an optimized build~~ (done 2026-11-10 in CI). The standalone E-01 smoke script has not been re-run on Linux; E-11 covers the same primitives.
2. E-04: record the CI calibration (`kdf-calibration-linux.json` in the `bench-linux` artifact) and the session login numbers, then decide whether to change the default parameters. A local Windows run under memory pressure (0.8 GiB free) was discarded.
3. Run E-11 against PostgreSQL to replace SQLite's page-quantized storage numbers.
4. E-03, remaining half: cross-check key generation (NIST keyGen vectors need seeded keygen, exposed by the liboqs C API but not by liboqs-python) and have a second implementation verify QuantumKey signatures.
5. E-09: fuzz `SignedMessage.decode` and the token frame parser.
6. E-06: port the token protocol to an MCU board and measure.
