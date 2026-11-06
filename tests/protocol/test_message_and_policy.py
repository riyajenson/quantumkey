import pytest

from quantumkey.protocol.message import MessageError, Operation, SignedMessage
from quantumkey.protocol.policy import Policy, PolicyError


def make(**overrides):
    base = dict(
        operation=Operation.LOGIN,
        rp_id=b"rp.example",
        transaction_id=b"tx-1",
        challenge=b"\x01" * 32,
        credential_id=b"cred-1",
        algorithm=b"ML-DSA-65",
        policy_hash=b"\x02" * 32,
    )
    base.update(overrides)
    return SignedMessage(**base)


def test_round_trip():
    message = make(extra=b"hello")
    assert SignedMessage.decode(message.encode()) == message


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation", Operation.REGISTER),
        ("rp_id", b"other.example"),
        ("transaction_id", b"tx-2"),
        ("challenge", b"\x03" * 32),
        ("credential_id", b"cred-2"),
        ("algorithm", b"ML-DSA-44"),
        ("policy_hash", b"\x04" * 32),
        ("extra", b"x"),
    ],
)
def test_every_field_changes_the_bytes(field, value):
    assert make().encode() != make(**{field: value}).encode()


def test_field_boundaries_are_unambiguous():
    # Moving a byte between adjacent fields must change the encoding.
    assert (
        make(rp_id=b"ab", transaction_id=b"c").encode()
        != make(rp_id=b"a", transaction_id=b"bc").encode()
    )


def test_strict_parser_rejects_bad_input():
    good = make().encode()
    for bad in (b"", good[:-1], good + b"\x00", b"Other/v1\x00" + good[14:]):
        with pytest.raises(MessageError):
            SignedMessage.decode(bad)
    unknown_op = good[:14] + b"\x09" + good[15:]
    with pytest.raises(MessageError):
        SignedMessage.decode(unknown_op)


def test_oversized_field_rejected():
    with pytest.raises(MessageError):
        make(extra=b"x" * 9000).encode()


def test_policy_digest_is_canonical():
    a = Policy(rp_id="rp.example", allowed_ops=("login", "migrate"))
    b = Policy(rp_id="rp.example", allowed_ops=("migrate", "login", "login"))
    assert a.digest() == b.digest()
    assert Policy.from_bytes(a.canonical_bytes()) == a
    with pytest.raises(PolicyError):
        Policy.from_bytes(b'{"rp_id": "rp.example"}')


def test_policy_checks():
    policy = Policy(
        rp_id="rp.example", allowed_ops=("login",), not_after=100, max_signs_per_minute=2
    )
    policy.check(Operation.LOGIN, "rp.example", 50, 1)
    with pytest.raises(PolicyError):
        policy.check(Operation.LOGIN, "evil.example", 50, 0)
    with pytest.raises(PolicyError):
        policy.check(Operation.MIGRATE, "rp.example", 50, 0)
    with pytest.raises(PolicyError):
        policy.check(Operation.LOGIN, "rp.example", 101, 0)
    with pytest.raises(PolicyError):
        policy.check(Operation.LOGIN, "rp.example", 50, 2)
