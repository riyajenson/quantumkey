"""ADR 0009: the signer builds and policy-checks enroll and revoke messages itself,
in process and inside the virtual token."""

import pytest

from quantumkey import crypto
from quantumkey.authenticator.core import MigrationTarget, SignRequest, SigningCore, SigningRefused
from quantumkey.authenticator.token import VirtualToken, handle
from quantumkey.protocol.message import Operation, SignedMessage
from quantumkey.protocol.migration import migration_binding, revocation_binding
from quantumkey.protocol.policy import Policy

RP = "rp.example"
CHALLENGE = b"\x05" * 32
TARGET = MigrationTarget("new-cred", "ML-DSA-44", b"\x01" * 1312, b"\x02" * 32)


def make_core(policy=None):
    core = SigningCore()
    public, _ = core.create("ML-DSA-44", policy or Policy(rp_id=RP), "c1")
    return core, public


def expected(public, operation, extra):
    return SignedMessage(
        operation, RP.encode(), b"tx", CHALLENGE, b"c1", b"ML-DSA-44", public.policy.digest(), extra
    ).encode()


def test_enroll_signature_covers_the_new_credential_binding():
    core, public = make_core()
    signature = core.sign("c1", SignRequest(Operation.ENROLL, RP, "tx", CHALLENGE, target=TARGET))
    binding = migration_binding(*vars(TARGET).values())
    assert crypto.verify("ML-DSA-44", public.public_key, expected(public, Operation.ENROLL, binding), signature)
    # The same signature is not a migrate authorization.
    assert not crypto.verify("ML-DSA-44", public.public_key, expected(public, Operation.MIGRATE, binding), signature)


def test_revoke_signature_covers_the_target():
    core, public = make_core()
    signature = core.sign("c1", SignRequest(Operation.REVOKE, RP, "tx", CHALLENGE, revoke_target="lost"))
    ok = expected(public, Operation.REVOKE, revocation_binding("lost"))
    other = expected(public, Operation.REVOKE, revocation_binding("someone-else"))
    assert crypto.verify("ML-DSA-44", public.public_key, ok, signature)
    assert not crypto.verify("ML-DSA-44", public.public_key, other, signature)


@pytest.mark.parametrize(
    "request_",
    [
        SignRequest(Operation.ENROLL, RP, "tx", CHALLENGE),  # enroll needs a target
        SignRequest(Operation.REVOKE, RP, "tx", CHALLENGE),  # revoke needs a revoke target
        SignRequest(Operation.REVOKE, RP, "tx", CHALLENGE, target=TARGET, revoke_target="x"),
        SignRequest(Operation.LOGIN, RP, "tx", CHALLENGE, revoke_target="x"),
        SignRequest(Operation.MIGRATE, RP, "tx", CHALLENGE, target=TARGET, revoke_target="x"),
        SignRequest(Operation.REVOKE, RP, "tx", CHALLENGE, revoke_target=""),
    ],
    ids=["enroll-no-target", "revoke-no-target", "revoke-with-both", "login-with-revoke",
         "migrate-with-revoke", "revoke-empty-target"],
)
def test_malformed_account_requests_are_refused(request_):
    core, _ = make_core()
    with pytest.raises(SigningRefused):
        core.sign("c1", request_)


def test_policy_without_enroll_or_revoke_refuses_both():
    core, _ = make_core(Policy(rp_id=RP, allowed_ops=("login", "migrate")))
    with pytest.raises(SigningRefused, match="not allowed"):
        core.sign("c1", SignRequest(Operation.ENROLL, RP, "tx", CHALLENGE, target=TARGET))
    with pytest.raises(SigningRefused, match="not allowed"):
        core.sign("c1", SignRequest(Operation.REVOKE, RP, "tx", CHALLENGE, revoke_target="x"))


def test_virtual_token_signs_enroll_and_revoke_out_of_process():
    with VirtualToken() as token:
        public = token.create_credential("ML-DSA-44", Policy(rp_id=RP), "c1")
        signature = token.sign("c1", SignRequest(Operation.REVOKE, RP, "tx", CHALLENGE, revoke_target="lost"))
        assert crypto.verify(
            "ML-DSA-44", public.public_key, expected(public, Operation.REVOKE, revocation_binding("lost")), signature
        )
        assert token.sign("c1", SignRequest(Operation.ENROLL, RP, "tx", CHALLENGE, target=TARGET))


def test_token_rejects_a_non_string_revoke_target():
    core, _ = make_core()
    reply = handle(core, {"cmd": "sign", "credential_id": "c1", "operation": 5, "rp_id": RP,
                          "transaction_id": "tx", "challenge": crypto.b64e(CHALLENGE),
                          "target": None, "revoke_target": 7})
    assert reply == {"ok": False, "error": "malformed request"}
