# ML-DSA Experiment Results

Do not commit private keys, secret-key bytes, random seeds, or sensitive machine information.

## Run metadata

| Item | Value |
|---|---|
| Date/time and timezone | 2026-10-26, Asia/Calcutta |
| Git commit | Phase 2 branch based on Phase 1 commit `4460557` |
| Operating system | Windows 11 x64 (build 26200) |
| CPU and architecture | Intel Core Ultra 5 125H, AMD64 |
| Installed RAM | 15.4 GiB |
| Python version | 3.12.10 |
| liboqs version/commit | 0.16.0 / `5a1a854b0dc9f2141bdc771c555ee60c37950183` |
| liboqs-python version/commit | 0.16.0.1 (PyPI release) |
| Build configuration | Visual Studio 18, MSVC 19.51.36260, Debug; default liboqs options |
| Runs and iterations per variant | 3 runs × 100 iterations (300 total) |
| Challenge size | 32 bytes |

## Command

From the repository root:

```powershell
python phase-1/02-crypto-hardware-riya/experiments/mldsa_smoke_test.py --iterations 100
```

The script writes JSON to standard output. Redirect it to a local file only if the output has been reviewed and contains no sensitive paths or machine identifiers.

## Results summary

| Variant | Keygen median | Sign median | Verify median | Public key | Private key | Signature |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | 0.455–0.469 ms (p95 0.613–0.774) | 1.698–2.015 ms (p95 5.441–5.593) | 0.570–0.602 ms (p95 0.797–0.914) | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | 0.781–0.794 ms (p95 1.156–1.253) | 2.662–2.965 ms (p95 7.623–9.118) | 0.859–0.870 ms (p95 1.271–1.386) | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | 1.054–1.239 ms (p95 1.460–1.823) | 3.041–3.490 ms (p95 6.555–8.021) | 1.175–1.381 ms (p95 1.690–2.216) | 2,592 B | 4,896 B | 4,627 B |

## Correctness checks

| Check | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| Valid signature accepted | Yes | Yes | Yes |
| Modified message rejected | Yes | Yes | Yes |
| Modified signature rejected | Yes | Yes | Yes |
| Observed sizes match FIPS 204 | Yes | Yes | Yes |

## Observations

All three standardized mechanisms were enabled and passed 300 key-generation, signing, and verification iterations, including both negative checks in every iteration. Means (keygen/sign/verify, ms) ranged across the three runs from 0.501–0.533/2.282–2.514/0.636–0.642 for ML-DSA-44, 0.838–0.884/3.304–3.731/0.893–0.967 for ML-DSA-65, and 1.140–1.340/3.480–4.137/1.284–1.511 for ML-DSA-87. Private keys remained in process memory and were not printed or written by the experiment.

## Anomalies and limitations

The wrapper automatically fetched and built the matching liboqs 0.16.0 source on first import. MSVC emitted liboqs warnings that its optimization barrier is not guaranteed for unsupported toolchains and compiler output may not be constant-time. Results came from a Debug build, three sequential runs, without a warm-up; treat them as compatibility and comparative research evidence, not production performance or security assurance. Context-string methods exist in the wrapper, but their behavior was not exercised by this run. See [`phase2/DEVELOPMENT.md`](../../../phase2/DEVELOPMENT.md) for the setup and limitations.

