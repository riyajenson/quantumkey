# NIST ACVP test vectors for ML-DSA

`ml-dsa-sigver-pure.json.gz` holds the 45 FIPS 204 signature-verification vectors (ML-DSA-44, -65 and -87, 15 each) for `ML-DSA.Verify` with a context string: the ACVP test groups with `signatureInterface: external`, `preHash: pure` and `externalMu: false`. Each vector gives a public key, message, context, signature, the expected result and, for invalid ones, the reason (modified message, or modified signature in the commitment, hint or z).

- **Source:** `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json` in [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) at commit `975de31eb83d87039ec88934fdc47d8c312b892d`. NIST publishes these as a US government work.
- **Changes:** other test groups dropped; secret keys removed (verification does not use them).
- **Regenerate:** `python scripts/extract_acvp_sigver.py <internalProjection.json> 975de31eb83d87039ec88934fdc47d8c312b892d tests/data/acvp/ml-dsa-sigver-pure.json.gz`. The output is byte-identical for the same input.
- **Used by:** `tests/protocol/test_acvp.py` (experiment E-03).
