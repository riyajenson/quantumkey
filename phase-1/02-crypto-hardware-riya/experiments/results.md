# ML-DSA Experiment Results

Do not commit private keys, secret-key bytes, random seeds, or sensitive machine information.

## Run metadata

| Item | Value |
|---|---|
| Date/time and timezone | TBD |
| Git commit | TBD |
| Operating system | TBD |
| CPU and architecture | TBD |
| Installed RAM | TBD |
| Python version | TBD |
| liboqs version/commit | TBD |
| liboqs-python version/commit | TBD |
| Build configuration | TBD |
| Iterations per variant | TBD |
| Challenge size | TBD |

## Command

From the repository root:

```powershell
python phase-1/02-crypto-hardware-riya/experiments/mldsa_smoke_test.py --iterations 100
```

The script writes JSON to standard output. Redirect it to a local file only if the output has been reviewed and contains no sensitive paths or machine identifiers.

## Results summary

| Variant | Keygen median | Sign median | Verify median | Public key | Private key | Signature |
|---|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | TBD | TBD | TBD | TBD | TBD | TBD |
| ML-DSA-65 | TBD | TBD | TBD | TBD | TBD | TBD |
| ML-DSA-87 | TBD | TBD | TBD | TBD | TBD | TBD |

## Correctness checks

| Check | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| Valid signature accepted | TBD | TBD | TBD |
| Modified message rejected | TBD | TBD | TBD |
| Modified signature rejected | TBD | TBD | TBD |
| Observed sizes match FIPS 204 | TBD | TBD | TBD |

## Observations

TBD

## Anomalies and limitations

TBD

