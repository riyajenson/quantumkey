"""R-10: per-IP rate limiting and the request-size cap."""

import pytest
from fastapi.testclient import TestClient

from quantumkey.server.app import MAX_BODY_BYTES, RATE_LIMIT_PER_MINUTE, create_app
from tests.helpers import (
    RP_ID,
    FakeClock,
    database_url,
    login_body,
    login_signature,
    register,
)


@pytest.fixture
def clock():
    return FakeClock()


def make_client(tmp_path, clock, client_ip="203.0.113.1", **kwargs):
    app = create_app(database_url(tmp_path), rp_id=RP_ID, clock=clock, **kwargs)
    return TestClient(app, client=(client_ip, 50000))


def unknown_login(client):
    return client.post("/auth/login/start", json={"username": "nobody"})



# -- rate limiting ---------------------------------------------------------------


def test_defaults():
    assert RATE_LIMIT_PER_MINUTE == 60
    assert MAX_BODY_BYTES == 64 * 1024


def test_requests_over_the_limit_get_429_with_retry_after(tmp_path, clock):
    client = make_client(tmp_path, clock, rate_limit=5)
    clock.now += 20  # 20 s into the minute
    for _ in range(5):
        assert unknown_login(client).status_code == 404  # failed requests still count
    response = unknown_login(client)
    assert (response.status_code, response.json()) == (429, {"error": "rate_limited"})
    assert 1 <= int(response.headers["Retry-After"]) <= 60


def test_limit_resets_in_the_next_window(tmp_path, clock):
    client = make_client(tmp_path, clock, rate_limit=2)
    for _ in range(2):
        unknown_login(client)
    assert unknown_login(client).status_code == 429
    clock.now += 60
    assert unknown_login(client).status_code == 404


def test_clients_are_counted_separately(tmp_path, clock):
    url = database_url(tmp_path)
    app = create_app(url, rp_id=RP_ID, clock=clock, rate_limit=1)
    first = TestClient(app, client=("203.0.113.1", 1))
    second = TestClient(app, client=("203.0.113.2", 1))
    assert unknown_login(first).status_code == 404
    assert unknown_login(first).status_code == 429
    assert unknown_login(second).status_code == 404


def test_rate_limit_applies_only_to_auth_posts(tmp_path, clock):
    client = make_client(tmp_path, clock, rate_limit=1)
    for _ in range(3):
        assert client.get("/health").status_code == 200
    assert unknown_login(client).status_code == 404


def test_rate_limit_can_be_disabled(tmp_path, clock):
    client = make_client(tmp_path, clock, rate_limit=None)
    for _ in range(RATE_LIMIT_PER_MINUTE + 5):
        assert unknown_login(client).status_code == 404


def test_normal_register_and_login_fit_the_default_limit(tmp_path, clock):
    client = make_client(tmp_path, clock)
    cred = register(client, "alice")
    for _ in range(10):
        started = client.post("/auth/login/start", json={"username": "alice"}).json()
        response = client.post(
            "/auth/login/complete", json=login_body(started, cred, login_signature(started, cred))
        )
        assert response.status_code == 200


# -- request size ----------------------------------------------------------------


def test_oversized_body_gets_413(tmp_path, clock):
    client = make_client(tmp_path, clock)
    body = b'{"username":"' + b"a" * MAX_BODY_BYTES + b'"}'
    response = client.post(
        "/auth/login/start", content=body, headers={"content-type": "application/json"}
    )
    assert (response.status_code, response.json()) == (413, {"error": "request_too_large"})


def test_body_without_content_length_gets_411(tmp_path, clock):
    client = make_client(tmp_path, clock)

    def chunks():
        yield b'{"username":"nobody"}'

    response = client.post(
        "/auth/login/start", content=chunks(), headers={"content-type": "application/json"}
    )
    assert (response.status_code, response.json()) == (411, {"error": "length_required"})


def test_body_at_the_cap_is_accepted_by_the_size_check(tmp_path, clock):
    client = make_client(tmp_path, clock)
    padding = MAX_BODY_BYTES - len(b'{"username":"nobody","x":""}')
    body = b'{"username":"nobody","x":"' + b"a" * padding + b'"}'
    assert len(body) == MAX_BODY_BYTES
    response = client.post(
        "/auth/login/start", content=body, headers={"content-type": "application/json"}
    )
    assert response.status_code == 422  # reached the schema check (unknown field)

