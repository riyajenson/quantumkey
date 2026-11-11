"""E-09: seeded fuzzing of every parser that reads untrusted bytes.

Each parser must either accept an input or reject it with its own error type;
no other exception may escape. Inputs are random bytes, mutations of valid
encodings, and deeply nested JSON (which makes Python's json raise
RecursionError). Seeds are fixed, so any failure reproduces.
"""

import hashlib
import io
import json
import random
import struct

import pytest
from fastapi.testclient import TestClient

from quantumkey import crypto
from quantumkey.authenticator import token
from quantumkey.authenticator.core import SigningCore
from quantumkey.protocol.message import MessageError, Operation, SignedMessage
from quantumkey.protocol.policy import Policy, PolicyError
from quantumkey.server.app import create_app
from tests.helpers import RP_ID, database_url, message, new_cred, start_registration

ROUNDS = 3000
DEEP = [b"[" * 50_000, b'{"a":' * 50_000, b"[" * 50_000 + b"]" * 50_000]
DEEP_IDS = ["arrays", "objects", "balanced"]


def mutate(rng: random.Random, data: bytes) -> bytes:
    data = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        choice = rng.randrange(5)
        if choice == 0 and data:  # flip a bit
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
        elif choice == 1 and data:  # truncate
            del data[rng.randrange(len(data)) :]
        elif choice == 2:  # insert random bytes
            i = rng.randrange(len(data) + 1)
            data[i:i] = rng.randbytes(rng.randint(1, 8))
        elif choice == 3 and len(data) >= 4:  # overwrite four bytes (hits length fields)
            i = rng.randrange(len(data) - 3)
            data[i : i + 4] = struct.pack(">I", rng.choice([0, 1, 2**31, 2**32 - 1, rng.randrange(2**32)]))
        elif data:  # duplicate a slice
            i = rng.randrange(len(data))
            data[i:i] = data[i : i + rng.randint(1, 16)]
    return bytes(data)


def random_message(rng: random.Random) -> SignedMessage:
    blob = lambda: rng.randbytes(rng.randint(0, 64))  # noqa: E731
    return SignedMessage(rng.choice(list(Operation)), blob(), blob(), blob(), blob(), blob(), blob(), blob())


# -- SignedMessage ---------------------------------------------------------------


def test_signed_message_round_trips():
    rng = random.Random(1)
    for _ in range(ROUNDS):
        original = random_message(rng)
        assert SignedMessage.decode(original.encode()) == original


def test_signed_message_decode_only_raises_message_error():
    rng = random.Random(2)
    seeds = [random_message(rng).encode() for _ in range(50)]
    for i in range(ROUNDS):
        data = rng.randbytes(rng.randint(0, 200)) if i % 5 == 0 else mutate(rng, rng.choice(seeds))
        try:
            decoded = SignedMessage.decode(data)
        except MessageError:
            continue
        assert decoded.encode() == data  # anything accepted is canonical


# -- Policy ----------------------------------------------------------------------


@pytest.mark.parametrize("data", DEEP, ids=DEEP_IDS)
def test_policy_rejects_deeply_nested_json(data):
    with pytest.raises(PolicyError):
        Policy.from_bytes(data)


def test_policy_from_bytes_only_raises_policy_error():
    rng = random.Random(3)
    seeds = [
        Policy(rp_id="rp.example", allowed_ops=("login",), not_after=n, max_signs_per_minute=m).canonical_bytes()
        for n, m in ((None, 1), (100, 30), (2**31, 999))
    ]
    for i in range(ROUNDS):
        data = rng.randbytes(rng.randint(0, 120)) if i % 5 == 0 else mutate(rng, rng.choice(seeds))
        try:
            policy = Policy.from_bytes(data)
        except PolicyError:
            continue
        assert policy.canonical_bytes() == data


# -- HTTP API ----------------------------------------------------------------------


def test_registration_with_a_deeply_nested_policy_is_422_not_500(tmp_path):
    client = TestClient(create_app(database_url(tmp_path), rp_id=RP_ID, rate_limit=None),
                        raise_server_exceptions=False)
    cred = new_cred()
    started = start_registration(client, "alice").json()
    signature = crypto.sign(
        cred.algorithm, cred.private_key,
        message(Operation.REGISTER, started, cred, extra=hashlib.sha256(cred.public_key).digest()),
    )
    response = client.post(
        "/auth/register/complete",
        json={
            "transaction_id": started["transaction_id"],
            "credential_id": cred.credential_id,
            "public_key": crypto.b64e(cred.public_key),
            "policy": crypto.b64e(b"[" * 6000),
            "signature": crypto.b64e(signature),
        },
    )
    assert (response.status_code, response.json()) == (422, {"error": "invalid_policy"})
