"""ADR 0009 through the CLI: enroll a second vault, then revoke the first."""

import pytest
from fastapi.testclient import TestClient

from quantumkey.authenticator import cli
from quantumkey.authenticator.vault import Vault
from quantumkey.server.app import create_app
from tests.helpers import RP_ID, database_url


@pytest.fixture
def app(tmp_path, monkeypatch):
    app = create_app(database_url(tmp_path), rp_id=RP_ID)
    # The CLI opens httpx.Client(base_url=...); hand it the in-process app instead.
    monkeypatch.setattr(cli.httpx, "Client", lambda **_: TestClient(app))
    return app


def run(monkeypatch, capsys, args, pin="1111", new_pin=None):
    monkeypatch.setenv("QK_PIN", pin)
    if new_pin:
        monkeypatch.setenv("QK_NEW_PIN", new_pin)
    else:
        monkeypatch.delenv("QK_NEW_PIN", raising=False)
    code = cli.main(["--rp-id", RP_ID, *args])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_enroll_a_second_vault_then_revoke_the_first(app, tmp_path, monkeypatch, capsys):
    laptop, phone = str(tmp_path / "laptop.sqlite3"), str(tmp_path / "phone.sqlite3")
    token = app.state.rp.issue_invite("alice")
    code, out, _ = run(monkeypatch, capsys, ["--vault", laptop, "register", "alice", "--invite", token])
    assert code == 0
    laptop_id = out.split()[-1]

    code, out, err = run(
        monkeypatch, capsys,
        ["--vault", laptop, "enroll", "alice", laptop_id, "--new-vault", phone], new_pin="2222",
    )
    assert code == 0, err
    assert out.startswith("enrolled ")
    phone_id = out.split()[1]
    assert [c.credential_id for c in Vault(phone).list_credentials()] == [phone_id]

    code, out, err = run(
        monkeypatch, capsys,
        ["--vault", phone, "revoke", "alice", laptop_id, "--with", phone_id], pin="2222",
    )
    assert code == 0, err
    assert f"revoked {laptop_id}" in out
    assert TestClient(app).get(f"/credentials/{laptop_id}").json()["status"] == "revoked"

    code, _, err = run(monkeypatch, capsys, ["--vault", laptop, "login", "alice"])
    assert code == 1


def test_revoking_the_last_credential_is_reported(app, tmp_path, monkeypatch, capsys):
    laptop = str(tmp_path / "laptop.sqlite3")
    token = app.state.rp.issue_invite("alice")
    _, out, _ = run(monkeypatch, capsys, ["--vault", laptop, "register", "alice", "--invite", token])
    laptop_id = out.split()[-1]
    code, _, err = run(
        monkeypatch, capsys, ["--vault", laptop, "revoke", "alice", laptop_id, "--with", laptop_id]
    )
    assert code == 1 and "last_credential" in err


def test_login_from_an_enrolled_device_uses_its_own_credential(app, tmp_path, monkeypatch, capsys):
    laptop, phone = str(tmp_path / "laptop.sqlite3"), str(tmp_path / "phone.sqlite3")
    token = app.state.rp.issue_invite("alice")
    _, out, _ = run(monkeypatch, capsys, ["--vault", laptop, "register", "alice", "--invite", token])
    laptop_id = out.split()[-1]
    run(monkeypatch, capsys, ["--vault", laptop, "enroll", "alice", laptop_id, "--new-vault", phone],
        new_pin="2222")
    # No --credential-id: the phone vault's only credential is used, not the
    # account's oldest (the laptop's, which this vault does not hold).
    code, out, err = run(monkeypatch, capsys, ["--vault", phone, "login", "alice"], pin="2222")
    assert (code, out.strip()) == (0, "login ok"), err


def test_devices_lists_the_accounts_credentials(app, tmp_path, monkeypatch, capsys):
    laptop, phone = str(tmp_path / "laptop.sqlite3"), str(tmp_path / "phone.sqlite3")
    token = app.state.rp.issue_invite("alice")
    _, out, _ = run(monkeypatch, capsys, ["--vault", laptop, "register", "alice", "--invite", token])
    laptop_id = out.split()[-1]
    _, out, _ = run(
        monkeypatch, capsys,
        ["--vault", laptop, "enroll", "alice", laptop_id, "--new-vault", phone], new_pin="2222",
    )
    phone_id = out.split()[1]
    run(monkeypatch, capsys, ["--vault", phone, "revoke", "alice", laptop_id, "--with", phone_id],
        pin="2222")
    code, out, err = run(monkeypatch, capsys, ["--vault", phone, "devices", "alice"], pin="2222")
    assert code == 0, err
    rows = {line.split()[0]: line.split()[1] for line in out.strip().splitlines()[1:]}
    assert rows == {laptop_id: "revoked", phone_id: "active"}
    assert "this vault" in next(line for line in out.splitlines() if line.startswith(phone_id))
    # The session used for listing was logged out afterwards.
    with app.state.rp.engine.connect() as connection:
        from sqlalchemy import text

        assert connection.execute(text("SELECT count(*) FROM sessions")).scalar() == 0
