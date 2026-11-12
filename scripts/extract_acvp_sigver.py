"""Regenerate tests/data/acvp/ml-dsa-sigver-pure.json.gz from NIST's ACVP vectors.

    python scripts/extract_acvp_sigver.py <internalProjection.json> <ACVP-Server commit> <output>

The input is gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json from
https://github.com/usnistgov/ACVP-Server at the given commit. The script reads it
as data only. It keeps the test groups for FIPS 204 ML-DSA.Verify with a context
string (external interface, pure, no external mu) and drops the secret keys,
which verification does not use.
"""

import gzip
import json
import sys


def main(src: str, sha: str, out: str) -> None:
    with open(src, encoding="utf-8") as handle:
        document = json.load(handle)
    vectors = [
        {
            "tcId": test["tcId"],
            "parameterSet": group["parameterSet"],
            "pk": test["pk"],
            "message": test["message"],
            "context": test["context"],
            "signature": test["signature"],
            "testPassed": test["testPassed"],
            "reason": test["reason"],
        }
        for group in document["testGroups"]
        if group["signatureInterface"] == "external"
        and group["preHash"] == "pure"
        and not group["externalMu"]
        for test in group["tests"]
    ]
    extract = {
        "source": "https://github.com/usnistgov/ACVP-Server/blob/"
        f"{sha}/gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json",
        "selection": "testGroups with signatureInterface=external, preHash=pure, "
        "externalMu=false; secret keys removed",
        "vectors": vectors,
    }
    raw = json.dumps(extract, separators=(",", ":"), sort_keys=True).encode()
    with open(out, "wb") as handle:
        handle.write(gzip.compress(raw, 9, mtime=0))  # mtime=0: byte-identical on rerun
    print(f"{len(vectors)} vectors -> {out}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
