# Phase 1 - ML-DSA, liboqs, and Hardware Feasibility

**Owner:** Riya

**Phase:** Research, requirements, and threat model

**Status:** In progress

## Objective

Determine whether ML-DSA can support QuantumKey as a software authenticator today and whether the same signing contract can later be implemented by an FPGA, Raspberry Pi Pico, or another microcontroller.

This folder contains research and a standalone validation experiment. It does not contain production authenticator or backend code.

## Questions to answer

1. Which ML-DSA variants are standardized, and what are their security/size trade-offs?
2. Can `liboqs` and `liboqs-python` generate keys, sign, and verify reliably on the development platform?
3. What exact library versions and build configuration were tested?
4. What latency, key-size, and signature-size results are observed locally?
5. What constraints affect Linux single-board computers, the RP2040/Pico, general MCUs, and FPGAs?
6. Which variant should QuantumKey use initially?
7. What must the future signing interface hide from the rest of the application?

## Deliverables

| File | Purpose |
|---|---|
| `mldsa-variants.md` | Comparison of ML-DSA-44, ML-DSA-65, and ML-DSA-87 |
| `liboqs-validation.md` | Reproducible environment and compatibility validation |
| `hardware-constraints.md` | Hardware feasibility questions and evidence |
| `recommendation.md` | Final recommendation, assumptions, and unresolved risks |
| `experiments/mldsa_smoke_test.py` | Standalone keygen/sign/verify experiment |
| `experiments/results.md` | Recorded results and environment information |

## Definition of done

- [ ] FIPS 204 is used as the authority for ML-DSA parameters and sizes.
- [ ] All three variants are compared.
- [ ] Exact `liboqs` and `liboqs-python` versions are recorded.
- [ ] Enabled ML-DSA mechanisms are enumerated at runtime.
- [ ] Key generation, signing, and valid verification succeed.
- [ ] Modified-message and modified-signature verification fail.
- [ ] Key and signature sizes match the expected values.
- [ ] Timing results include iteration count, median, mean, and p95.
- [ ] Desktop/SBC, RP2040, generic MCU, and FPGA constraints are treated separately.
- [ ] A provisional default variant is recommended with evidence.
- [ ] Assumptions, risks, and unanswered questions are explicit.
- [ ] No private key or secret key material is committed or printed.

## Authoritative references

- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Open Quantum Safe liboqs](https://github.com/open-quantum-safe/liboqs)
- [Open Quantum Safe liboqs-python](https://github.com/open-quantum-safe/liboqs-python)
- [liboqs platform-specific build notes](https://github.com/open-quantum-safe/liboqs/wiki/Platform-specific-notes-for-building-liboqs)
