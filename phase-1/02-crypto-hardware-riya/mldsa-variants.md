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

Measured on Windows 11 x64, Intel Core Ultra 5 125H, liboqs 0.16.0 Debug build (3 runs x 100 iterations; ranges are across runs). See [`experiments/results.md`](experiments/results.md). End-to-end figures come from the prototype benchmark in [`docs/evaluation/bench-2026-11-06.json`](../../docs/evaluation/bench-2026-11-06.json).

| Criterion | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| Security category | 2 | 3 | 5 |
| Key-generation median | 0.46–0.47 ms | 0.78–0.79 ms | 1.05–1.24 ms |
| Signing median | 1.70–2.02 ms | 2.66–2.97 ms | 3.04–3.49 ms |
| Verification median | 0.57–0.60 ms | 0.86–0.87 ms | 1.18–1.38 ms |
| Observed public-key size | 1,312 B | 1,952 B | 2,592 B |
| Observed private-key size | 2,560 B | 4,032 B | 4,896 B |
| Observed signature size | 2,420 B | 3,309 B | 4,627 B |
| Desktop suitability | Suitable: latency imperceptible | Suitable: latency imperceptible | Suitable: latency imperceptible |
| Constrained-hardware suitability | Unmeasured; smallest buffers | Unmeasured | Unmeasured; largest buffers |
| Login request + response (prototype JSON) | 3,706 B | 4,890 B | 6,649 B |

Observed sizes match FIPS 204 Table 2, and liboqs exports the expanded private-key form (not the 32-byte seed). On the desktop, the variant choice changes login latency by well under 1% of the measured ~325 ms login, which is dominated by the vault's Argon2id unlock. The variant mainly affects payload size and storage.

## Questions for each variant

- What security category does it target?
- Do observed sizes match final FIPS 204 values?
- How much larger is a QuantumKey login request than a classical signature request?
- Is latency perceptible during interactive login?
- How much RAM is required during signing and verification?
- Is the implementation available and enabled in the selected liboqs build?
- Does the implementation expose FIPS 204 context-string operations?
- Does the target hardware have sufficient RAM, flash, randomness, and protected storage?

## Provisional decision

ML-DSA-65 is the default (category 3, intermediate sizes). Local measurements support it for desktop use. The choice stays provisional until an optimized, constant-time-supported build is measured and hardware evidence exists. The prototype supports all three variants, and a credential can be moved to a different variant through migration.

## Sources

- NIST, [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf), especially Tables 1 and 2.
- Open Quantum Safe, [liboqs supported signature mechanisms](https://github.com/open-quantum-safe/liboqs).

