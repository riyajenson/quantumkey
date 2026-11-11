"""R-10: expired challenges and expired or used invites are purged."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from quantumkey.server.app import create_app
from quantumkey.server.models import Challenge, EnrollmentInvite
from quantumkey.server.service import PURGE_INTERVAL
from tests.helpers import (
    RP_ID,
    FakeClock,
    database_url,
    login_body,
    login_signature,
    register,
    start_registration,
)


@pytest.fixture
def clock():
    return FakeClock()


def make_client(tmp_path, clock, **kwargs):
    return TestClient(create_app(database_url(tmp_path), rp_id=RP_ID, clock=clock, **kwargs))


def count(client, model):
    with Session(client.app.state.rp.engine) as session:
        return session.scalar(select(func.count()).select_from(model))


def test_purge_removes_expired_challenges_and_spent_or_expired_invites(tmp_path, clock):
    client = make_client(tmp_path, clock)
    rp = client.app.state.rp
    register(client, "alice")  # one used challenge, one used invite
    rp.issue_invite("bob", ttl=30)  # will expire
    live_invite = rp.issue_invite("carol", ttl=3600)  # stays
    start_registration(client, "dave")  # dave's invite is unused; his challenge is live
    clock.now += 45  # both challenges (60 s) still live; bob's invite (30 s) expired
    assert rp.purge_expired() == (0, 2)  # alice's used invite and bob's expired one
    clock.now += 30  # both challenges now expired
    assert rp.purge_expired() == (2, 0)
    assert count(client, Challenge) == 0
    assert count(client, EnrollmentInvite) == 2  # carol's and dave's
    assert client.post(
        "/auth/register/start", json={"username": "carol", "invite": live_invite}
    ).status_code == 200


def test_live_challenge_survives_a_purge(tmp_path, clock):
    client = make_client(tmp_path, clock)
    cred = register(client, "alice")
    started = client.post("/auth/login/start", json={"username": "alice"}).json()
    clock.now += 30
    client.app.state.rp.purge_expired()
    response = client.post(
        "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
    )
    assert response.status_code == 200


def test_automatic_purge_runs_at_most_once_per_interval(tmp_path, clock):
    assert PURGE_INTERVAL == 60
    client = make_client(tmp_path, clock, rate_limit=None, challenge_ttl=10)
    start_login = lambda: client.post("/auth/login/start", json={"username": "alice"})  # noqa: E731
    t0 = clock.now
    register(client, "alice")  # first issue purges (nothing to remove); challenge A
    clock.now = t0 + 61
    start_login()  # interval passed: A purged; challenge B
    assert count(client, Challenge) == 1
    clock.now = t0 + 100
    start_login()  # B expired, but only 39 s since the last purge: kept; challenge C
    assert count(client, Challenge) == 2
    clock.now = t0 + 125
    start_login()  # 64 s since the last purge: B and C purged; challenge D
    assert count(client, Challenge) == 1


def test_admin_purge_command(tmp_path, clock, capsys):
    from quantumkey.server import admin

    url = database_url(tmp_path)
    client = TestClient(create_app(url, rp_id=RP_ID))
    client.app.state.rp.issue_invite("bob", ttl=-1)  # already expired
    assert admin.main(["--database-url", url, "purge"]) == 0
    assert capsys.readouterr().out.strip() == "purged 0 challenges, 1 invites"
