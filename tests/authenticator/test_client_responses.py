"""E-09: the protocol client turns a malformed server response into
ServerRejected instead of crashing (proxy error pages, hostile servers)."""

import pytest

from quantumkey.authenticator.client import AuthClient, ServerRejected


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.content = body

    def json(self):
        import json

        return json.loads(self.content)


class FakeHttp:
    def __init__(self, response):
        self.response = response

    def post(self, path, json=None):  # noqa: A002 - mirrors httpx
        return self.response


@pytest.mark.parametrize(
    "status, body",
    [(502, b"<html>Bad Gateway</html>"), (200, b"[" * 50_000), (200, b"[1, 2]"), (400, b'"text"')],
    ids=["html-error-page", "deeply-nested", "not-an-object", "string-error"],
)
def test_malformed_responses_become_server_rejected(status, body):
    client = AuthClient(FakeHttp(FakeResponse(status, body)), "rp.example")
    with pytest.raises(ServerRejected) as error:
        client._post("/auth/login/start", {"username": "alice"})
    assert error.value.code == "invalid_response"
    assert error.value.status == status
