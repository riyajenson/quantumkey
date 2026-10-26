# Phase 2 Validation Results

**Run date:** 2026-10-26 (Asia/Calcutta)

**Code base:** Phase 2 branch based on Phase 1 commit `4460557` and root documentation commit `8fe37df`

**Environment:** Windows 11 x64; Python 3.12.10; Intel Core Ultra 5 125H; 15.4 GiB RAM; MSVC 19.51.36260; CMake 4.4.4; Visual Studio Debug build
**Cryptography:** liboqs 0.16.0, source commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`; liboqs-python 0.16.0.1

## ML-DSA experiment

Command:

```powershell
python phase-1\02-crypto-hardware-riya\experiments\mldsa_smoke_test.py --iterations 100
```

The wrapper enabled ML-DSA-44, ML-DSA-65, and ML-DSA-87. For each variant, 100 keypairs were generated, each key signed a 32-byte challenge, valid signatures verified, and both altered messages and altered signatures were rejected in every iteration. Observed public/private/signature sizes matched the values recorded from FIPS 204.

Three sequential runs of 100 iterations each were completed per variant (300 operations per variant). Cells show the range across the three run summaries as **median / mean / p95**, in milliseconds.

| Variant | Security category | Key generation (median / mean / p95 ms) | Signing (median / mean / p95 ms) | Verification (median / mean / p95 ms) | Public key (B) | Private key (B) | Signature (B) |
|---|---:|---:|---:|---:|---:|---:|---:|
| ML-DSA-44 | 2 | 0.455–0.469 / 0.501–0.533 / 0.613–0.774 | 1.698–2.015 / 2.282–2.514 / 5.441–5.593 | 0.570–0.602 / 0.636–0.642 / 0.797–0.914 | 1,312 | 2,560 | 2,420 |
| ML-DSA-65 | 3 | 0.781–0.794 / 0.838–0.884 / 1.156–1.253 | 2.662–2.965 / 3.304–3.731 / 7.623–9.118 | 0.859–0.870 / 0.893–0.967 / 1.271–1.386 | 1,952 | 4,032 | 3,309 |
| ML-DSA-87 | 5 | 1.054–1.239 / 1.140–1.340 / 1.460–1.823 | 3.041–3.490 / 3.480–4.137 / 6.555–8.021 | 1.175–1.381 / 1.284–1.511 / 1.690–2.216 | 2,592 | 4,896 | 4,627 |

Measurements came from the default Visual Studio Debug build, without a separate warm-up. Run-to-run variation is retained above rather than presented as a release performance estimate.

## API, database, and vault E2E

The E2E test starts a separate Uvicorn process and uses real HTTP requests. It passed for all three variants, both in the original environment and in a fresh Python virtual environment installed from the lock file (the fresh-venv run reused the already-built native liboqs installation). It exercises local credential persistence and unlock, public-key registration and binary retrieval over FastAPI/SQLAlchemy/SQLite, signature verification using the stored key, modified-message rejection, wrong-PIN rejection, modified vault metadata rejection, and absence of private-key bytes in the local vault file and API response.

The local vault proof uses a random 16-byte salt, Argon2id (time cost 3, memory 65,536 KiB, parallelism 1), a random 12-byte nonce, and AES-256-GCM. Credential ID and algorithm are authenticated as associated data. The wrong-PIN error does not distinguish a bad PIN from damaged vault data.

Validated Python stack: FastAPI 0.162.0, SQLAlchemy 2.1.6, SQLite, httpx 0.28.1, Uvicorn 0.54.0, cryptography 50.0.2, and argon2-cffi 25.1.0. PostgreSQL validation is still open: Docker CLI 29.7.2 is present, but `docker info` could not connect to `npipe:////./pipe/dockerDesktopLinuxEngine`; no local PostgreSQL client or service is installed. The required PostgreSQL E2E evidence is the same registration, binary key retrieval, and signature verification flow, plus transaction rollback/commit, duplicate-key conflict behavior, and persistence after a service restart. Database migrations, concurrency behavior, challenge lifecycle, and network TLS were not tested.

## Conclusion

**Status: Crypto and SQLite/vault experiments validated; PostgreSQL gate open.** The liboqs wrapper and all three standardized ML-DSA variants work reproducibly in this Windows environment; key and signature sizes match the Phase 1 FIPS 204 reference. The API/database and encrypted-vault choices also work together in the Phase 2 E2E prototype using SQLite. The native MSVC timing-safety warning blocks any security assurance claim, the Debug build limits performance conclusions, and PostgreSQL plus cross-platform reproducibility remain unvalidated. Phase 2 should not be marked fully complete until PostgreSQL E2E evidence is available or the team records a reasoned alternative decision.

ML-DSA-65 remains the provisional software prototype candidate because it offers category 3 security with intermediate sizes and timings. The current measurements are not sufficient to finalize the choice.
