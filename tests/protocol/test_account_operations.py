"""ADR 0009: enroll and revoke are distinct signed operations that policies can name."""

import pytest

from quantumkey.protocol.message import MessageError, Operation, SignedMessage
from quantumkey.protocol.migration import migration_binding, revocation_binding
from quantumkey.protocol.policy import Policy, PolicyError


def test_operation_codes_are_stable():
    assert [(op.name, int(op)) for op in Operation] == [
        ("REGISTER", 1), ("LOGIN", 2), ("MIGRATE", 3), ("ENROLL", 4), ("REVOKE", 5)
    ]


def test_enroll_and_migrate_messages_differ_for_the_same_binding():
    binding = migration_binding("new", "ML-DSA-65", b"pk", b"h" * 32)
    fields = (b"rp", b"tx", b"c" * 32, b"old", b"ML-DSA-65", b"p" * 32, binding)
    migrate = SignedMessage(Operation.MIGRATE, *fields).encode()
    enroll = SignedMessage(Operation.ENROLL, *fields).encode()
    assert migrate != enroll
    assert SignedMessage.decode(enroll).operation is Operation.ENROLL


def test_unknown_operation_byte_is_still_rejected():
    data = bytearray(SignedMessage(Operation.REVOKE, b"", b"", b"", b"", b"", b"").encode())
    data[len(b"QuantumKey/v1\x00")] = 6
    with pytest.raises(MessageError, match="unknown operation"):
        SignedMessage.decode(bytes(data))


def test_revocation_binding_is_length_prefixed_and_target_specific():
    assert len(revocation_binding("cred-a")) == 32
    assert revocation_binding("cred-a") != revocation_binding("cred-b")
    assert revocation_binding("ab") != revocation_binding("a") != revocation_binding("")


def test_policy_accepts_enroll_and_revoke():
    policy = Policy(rp_id="rp", allowed_ops=("login", "enroll", "revoke"))
    parsed = Policy.from_bytes(policy.canonical_bytes())
    assert parsed.canonical_bytes() == policy.canonical_bytes()
    assert set(parsed.allowed_ops) == {"login", "enroll", "revoke"}


def test_default_policy_allows_all_five_operations():
    assert set(Policy(rp_id="rp").allowed_ops) == {"register", "login", "migrate", "enroll", "revoke"}


def test_policy_still_rejects_unknown_operations():
    with pytest.raises(PolicyError):
        Policy(rp_id="rp", allowed_ops=("login", "delete_account"))
