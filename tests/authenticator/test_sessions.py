"""Phase 5: controlled unlocked sessions in the software signer, and the CLI
commands for deleting a credential and changing the PIN."""

import pytest

from quantumkey.authenticator import cli
from quantumkey.authenticator.core import SignRequest, SigningRefused
from quantumkey.authenticator.software import SoftwareSigner
from quantumkey.authenticator.vault import KdfParams, Vault, VaultUnlockError
from quantumkey.protocol.message import Operation
from quantumkey.protocol.policy import Policy
from tests.helpers import FakeClock

FAST = KdfParams(time_cost=1, memory_kib=8192, parallelism=1)
RP = "rp.example"


def request():
    return SignRequest(Operation.LOGIN, RP, "tx", b"\x01" * 32)


@pytest.fixture
def clock():
    return FakeClock()


def make_signer(tmp_path, clock, **kwargs):
    signer = SoftwareSigner(tmp_path / "v.sqlite3", "1234", clock, kdf=FAST, **kwargs)
    signer.create_credential("ML-DSA-44", Policy(rp_id=RP, max_signs_per_minute=100), "c1")
    return signer


def count_unlocks(signer, monkeypatch):
    calls = []
    real = signer.vault.unlock
    monkeypatch.setattr(signer.vault, "unlock", lambda *a: calls.append(a) or real(*a))
    return calls


def test_without_a_session_every_signature_unlocks(tmp_path, clock, monkeypatch):
    signer = make_signer(tmp_path, clock)
    calls = count_unlocks(signer, monkeypatch)
    for _ in range(3):
        signer.sign("c1", request())
    assert len(calls) == 3


def test_session_reuses_the_unlocked_key_until_it_expires(tmp_path, clock, monkeypatch):
    signer = make_signer(tmp_path, clock, unlock_ttl=300)
    calls = count_unlocks(signer, monkeypatch)
    signer.sign("c1", request())
    clock.now += 299
    signer.sign("c1", request())
    assert len(calls) == 1
    clock.now += 2  # 301 s after the unlock: the session has ended
    signer.sign("c1", request())
    assert len(calls) == 2


def test_session_lifetime_is_from_unlock_not_from_last_use(tmp_path, clock, monkeypatch):
    signer = make_signer(tmp_path, clock, unlock_ttl=100)
    calls = count_unlocks(signer, monkeypatch)
    for _ in range(4):  # used every 40 s, but the session still ends at 100 s
        signer.sign("c1", request())
        clock.now += 40
    assert len(calls) == 2


def test_lock_ends_the_session(tmp_path, clock, monkeypatch):
    signer = make_signer(tmp_path, clock, unlock_ttl=300)
    calls = count_unlocks(signer, monkeypatch)
    signer.sign("c1", request())
    signer.lock()
    signer.sign("c1", request())
    assert len(calls) == 2


def test_policy_is_still_enforced_inside_a_session(tmp_path, clock):
    signer = make_signer(tmp_path, clock, unlock_ttl=300)
    signer.sign("c1", request())
    with pytest.raises(SigningRefused, match="relying party"):
        signer.sign("c1", SignRequest(Operation.LOGIN, "evil.example", "tx", b"\x01" * 32))


def test_wrong_pin_never_opens_a_session(tmp_path, clock):
    make_signer(tmp_path, clock)
    wrong = SoftwareSigner(tmp_path / "v.sqlite3", "0000", clock, unlock_ttl=300)
    for _ in range(2):
        with pytest.raises(VaultUnlockError):
            wrong.sign("c1", request())


def test_deleting_a_credential_ends_its_session(tmp_path, clock):
    signer = make_signer(tmp_path, clock, unlock_ttl=300)
    signer.sign("c1", request())
    signer.delete_credential("c1")
    with pytest.raises(SigningRefused, match="unknown credential"):
        signer.sign("c1", request())


def test_negative_session_lifetime_is_rejected(tmp_path, clock):
    with pytest.raises(ValueError):
        SoftwareSigner(tmp_path / "v.sqlite3", "1234", clock, unlock_ttl=-1)


# -- CLI -------------------------------------------------------------------------


def run(monkeypatch, args, pin="1234", new_pin=None):
    monkeypatch.setenv("QK_PIN", pin)
    if new_pin is None:
        monkeypatch.delenv("QK_NEW_PIN", raising=False)
    else:
        monkeypatch.setenv("QK_NEW_PIN", new_pin)
    return cli.main(args)


def test_cli_delete_removes_the_credential_with_the_right_pin(tmp_path, clock, monkeypatch, capsys):
    make_signer(tmp_path, clock)
    vault = ["--vault", str(tmp_path / "v.sqlite3")]
    assert run(monkeypatch, [*vault, "delete", "c1"], pin="0000") == 1
    assert Vault(tmp_path / "v.sqlite3").list_credentials()
    assert run(monkeypatch, [*vault, "delete", "c1"]) == 0
    assert Vault(tmp_path / "v.sqlite3").list_credentials() == []
    out = capsys.readouterr().out
    assert "deleted c1" in out and "still active on the server" in out


def test_cli_delete_unknown_credential_fails(tmp_path, monkeypatch, capsys):
    assert run(monkeypatch, ["--vault", str(tmp_path / "v.sqlite3"), "delete", "nope"]) == 1
    assert "unknown credential" in capsys.readouterr().err


def test_cli_change_pin(tmp_path, clock, monkeypatch):
    make_signer(tmp_path, clock)
    vault = ["--vault", str(tmp_path / "v.sqlite3")]
    assert run(monkeypatch, [*vault, "change-pin"], new_pin="5678") == 0
    assert Vault(tmp_path / "v.sqlite3").unlock("5678", "c1")
    assert run(monkeypatch, [*vault, "change-pin"], pin="1234", new_pin="9999") == 1  # old PIN gone
