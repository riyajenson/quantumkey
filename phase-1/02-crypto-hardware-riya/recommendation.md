# Cryptography and Hardware Recommendation

**Status:** Provisional - crypto stack functionally validated on one Windows development machine; hardware and production-security evidence remain incomplete.

## Executive conclusion

The pinned liboqs-python/liboqs stack successfully generated keys, signed, and verified all three standardized ML-DSA variants, with expected FIPS 204 sizes. ML-DSA-65 remains the provisional software candidate because it provides category 3 security with intermediate signature and key sizes. Windows/MSVC produced a warning that constant-time optimization barriers are not guaranteed, so this evidence does not support a security assurance claim. Linux SBC, RP2040, generic MCU, and FPGA feasibility remain unvalidated and require target-specific memory, entropy, key-storage, and timing evidence.

## Decisions

| Decision | Recommendation | Evidence/confidence |
|---|---|---|
| Initial ML-DSA variant | Provisional candidate: ML-DSA-65 | 100 iterations passed; Debug measurements only |
| Variants retained for research | Provisional: 44, 65, and 87 | Needed for comparative benchmarks |
| Cryptographic provider | liboqs via liboqs-python 0.16.0.1 / liboqs 0.16.0 | Functional validation passed; MSVC timing-safety limitation |
| Primary development environment | Windows 11 x64, Python 3.12.10 | Reproduced once; pinned setup documented |
| Windows vs WSL/Docker setup | Native Windows build works for experiments; prefer supported constant-time toolchain for future assurance | WSL/Docker not tested |
| Linux SBC feasibility | Unverified | No target measurement |
| RP2040/Pico feasibility | Unverified | No portable implementation or peak-memory evidence |
| FPGA direction | Keep private key and signing policy in future token design | Hardware design and timing unvalidated |

## Required answers

1. **Does the stack provide keygen, private-key export/import, signing and verification?** Yes. `generate_keypair`, `export_secret_key`, construction with `secret_key=` and `sign`/`verify` all work for the three variants.
2. **Which mechanism names must the application use?** `ML-DSA-44`, `ML-DSA-65` and `ML-DSA-87` (standardized names, not legacy `Dilithium*`). They are listed in `quantumkey/crypto.py`.
3. **Best first-prototype trade-off?** ML-DSA-65 (category 3, intermediate sizes). All three remain supported.
4. **Are sizes acceptable for storage and API transport?** Yes for desktop. A login is 3.7–6.6 KB of JSON, and base64 adds about a third.
5. **Is interactive signing latency acceptable?** Yes. 1.7–3.5 ms median, negligible next to the ~256 ms vault unlock.
6. **Which environment gives every team member a reproducible setup?** Only native Windows 11 with the pinned lock file is validated. WSL/Docker/Linux remain open.
7. **Can a Linux SBC run the same backend?** Unverified; no measurement.
8. **Is an RP2040-class device feasible?** Uncertain. It is plausible for a functional token, but there is no protected key storage and the RNG is unverified (see `hardware-constraints.md`).
9. **What should a future FPGA handle?** Nothing yet. Keep the key and policy in a full token, and consider acceleration only after an MCU bottleneck is measured.
10. **What remains unverified?** Optimized and constant-time builds, non-Windows platforms, MCU memory/latency, side-channel behaviour, and ML-DSA context-string use.

## Security requirements carried forward

- Do not implement ML-DSA manually.
- Do not log, transmit, or commit private keys.
- Treat hardware keys as opaque handles so the host need not receive private-key bytes.
- Use cryptographically secure randomness supplied or approved by the implementation.
- Bind signatures to the QuantumKey protocol and operation type through a canonical signed message; evaluate ML-DSA context strings separately.
- Pin exact dependency versions for reproducible research.
- Distinguish standardized ML-DSA names from legacy Dilithium mechanism names.
- Do not claim hardware feasibility without peak-memory and execution evidence.

## Known risks

| Risk | Likelihood | Impact | Planned investigation/mitigation |
|---|---|---|---|
| Native Windows library setup is difficult to reproduce | Medium | Medium | Compare native, WSL, and Docker workflows |
| liboqs and wrapper versions are incompatible | Low (pinned) | High | Record and pin matching versions |
| Large signatures increase request/network cost | Known | Low (3.7–6.6 KB per login measured) | Measure encoded request sizes |
| MCU signing exceeds RAM or latency budget | Medium | High | Obtain measurements for concrete targets |
| Hardware lacks protected key storage | High for RP2040 | High | Make key protection a target-selection criterion |
| Side-channel resistance is insufficient | Unknown | High | Review implementation claims and threat model |

## Final recommendation

For software compatibility experiments, retain liboqs through liboqs-python and keep ML-DSA-65 as the provisional default. Before making a production-security or final performance claim, rerun on an approved constant-time toolchain with an optimized build. Hardware recommendations remain open until measurements exist for specific targets; see [`phase2/VALIDATION_RESULTS.md`](../../phase2/VALIDATION_RESULTS.md) for the complete current evidence.

