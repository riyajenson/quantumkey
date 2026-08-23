# ML-DSA Variant Comparison

## Scope

ML-DSA is the Module-Lattice-Based Digital Signature Algorithm standardized in NIST FIPS 204. It is derived from CRYSTALS-Dilithium. QuantumKey will use an established implementation; it will not implement ML-DSA manually.

## Standardized parameter sets

The byte sizes below are from Table 2 of the final FIPS 204 publication.

| Variant | NIST security category | Private key | Public key | Signature | Public key + signature |
|---|---:|---:|---:|---:|---:|
| ML-DSA-44 | 2 | 2,560 B | 1,312 B | 2,420 B | 3,732 B |
| ML-DSA-65 | 3 | 4,032 B | 1,952 B | 3,309 B | 5,261 B |
| ML-DSA-87 | 5 | 4,896 B | 2,592 B | 4,627 B | 7,219 B |

> The stored/expanded private-key representation exposed by a library may differ from a seed-form representation. Record the actual byte length returned by the selected `liboqs` API and do not silently mix representations in comparisons.

## Evaluation matrix

Complete this after running the experiment on the target development environment.

| Criterion | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| Security category | 2 | 3 | 5 |
| Key-generation median | TBD | TBD | TBD |
| Signing median | TBD | TBD | TBD |
| Verification median | TBD | TBD | TBD |
| Observed public-key size | TBD | TBD | TBD |
| Observed private-key size | TBD | TBD | TBD |
| Observed signature size | TBD | TBD | TBD |
| Desktop suitability | TBD | TBD | TBD |
| Constrained-hardware suitability | TBD | TBD | TBD |
| Network/storage impact | TBD | TBD | TBD |

## Questions for each variant

- What security category does it target?
- Do observed sizes match final FIPS 204 values?
- How much larger is a QuantumKey login request than a classical signature request?
- Is latency perceptible during interactive login?
- How much RAM is required during signing and verification?
- Is the implementation available and enabled in the selected liboqs build?
- Does the implementation expose FIPS 204 context-string operations?
- Does the target hardware have sufficient RAM, flash, randomness, and protected storage?

## Provisional hypothesis

ML-DSA-65 is the candidate default because it provides a middle security category and moderate size/performance trade-off. This is not a final choice. The recommendation must be updated after local measurements and hardware evidence are collected.

## Sources

- NIST, [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf), especially Tables 1 and 2.
- Open Quantum Safe, [liboqs supported signature mechanisms](https://github.com/open-quantum-safe/liboqs).

