"""E-03: liboqs agrees with NIST's ACVP vectors for FIPS 204 ML-DSA.Verify.

The vectors (tests/data/acvp/) are independent of liboqs: NIST generated them
with its own implementation. Every valid vector carries a non-empty context
string; QuantumKey signs with the empty context, so its own verify() must
reject those signatures (context domain separation) and agree on the rest.
"""

import gzip
import json
from pathlib import Path

import oqs
import pytest

from quantumkey import crypto

DATA = Path(__file__).resolve().parents[1] / "data" / "acvp" / "ml-dsa-sigver-pure.json.gz"
VECTORS = json.loads(gzip.decompress(DATA.read_bytes()))["vectors"]
IDS = [
    f"{v['parameterSet']}-tc{v['tcId']}-{'valid' if v['testPassed'] else 'invalid'}" for v in VECTORS
]


def fields(vector):
    return (bytes.fromhex(vector[k]) for k in ("pk", "message", "context", "signature"))


def test_vector_set_is_complete():
    by_set = {p: [v for v in VECTORS if v["parameterSet"] == p] for p in crypto.ALGORITHMS}
    assert {p: len(v) for p, v in by_set.items()} == {p: 15 for p in crypto.ALGORITHMS}
    assert all(any(v["testPassed"] for v in vs) for vs in by_set.values())


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_liboqs_matches_nist(vector):
    public_key, message, context, signature = fields(vector)
    with oqs.Signature(vector["parameterSet"]) as verifier:
        result = verifier.verify_with_ctx_str(message, signature, context, public_key)
    assert result is vector["testPassed"], vector["reason"]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_quantumkey_verify_uses_the_empty_context(vector):
    public_key, message, context, signature = fields(vector)
    expected = vector["testPassed"] and context == b""
    assert crypto.verify(vector["parameterSet"], public_key, message, signature) is expected
