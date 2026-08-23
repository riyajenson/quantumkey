# Cryptography and Hardware Recommendation

**Status:** Draft - complete after validation and evidence collection.

## Executive conclusion

TBD: State whether ML-DSA through liboqs is suitable for the first QuantumKey software prototype and summarize the hardware outlook in three to five sentences.

## Decisions

| Decision | Recommendation | Evidence/confidence |
|---|---|---|
| Initial ML-DSA variant | Provisional candidate: ML-DSA-65 | Must be confirmed by measurements |
| Variants retained for research | Provisional: 44, 65, and 87 | Needed for comparative benchmarks |
| Cryptographic provider | Provisional: liboqs via liboqs-python | Must pass compatibility validation |
| Primary development environment | TBD | TBD |
| Windows vs WSL/Docker setup | TBD | TBD |
| Linux SBC feasibility | TBD | TBD |
| RP2040/Pico feasibility | TBD | TBD |
| FPGA direction | TBD | TBD |

## Required answers

1. Does the tested Open Quantum Safe stack provide key generation, private-key export/import, signing, and verification?
2. Which exact mechanism names must the application use?
3. Which parameter set gives the best first-prototype trade-off?
4. Are key and signature sizes acceptable for storage and API transport?
5. Is interactive signing latency acceptable?
6. Which environment gives every team member a reproducible setup?
7. Can a Linux SBC run the same software backend?
8. Is an RP2040-class device feasible with available implementations and memory?
9. What should be handled by a future FPGA?
10. What facts remain unverified?

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
| Native Windows library setup is difficult to reproduce | TBD | TBD | Compare native, WSL, and Docker workflows |
| liboqs and wrapper versions are incompatible | TBD | TBD | Record and pin matching versions |
| Large signatures increase request/network cost | Known | TBD | Measure encoded request sizes |
| MCU signing exceeds RAM or latency budget | TBD | High | Obtain measurements for concrete targets |
| Hardware lacks protected key storage | TBD | High | Make key protection a target-selection criterion |
| Side-channel resistance is insufficient | TBD | High | Review implementation claims and threat model |

## Final recommendation

TBD after completing `liboqs-validation.md`, `hardware-constraints.md`, and the experiment results.

