"""Role-based bearer authorization for the real HTTP API."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from guard import api
from agent.tools import HttpGuard

AGENT_TOKEN = "agent-" + "a" * 40
VIEWER_TOKEN = "viewer-" + "v" * 40
APPROVER_TOKEN = "approver-" + "p" * 40
ADMIN_TOKEN = "admin-" + "d" * 40
ROLE_TOKENS = {
    "agent": AGENT_TOKEN,
    "viewer": VIEWER_TOKEN,
    "approver": APPROVER_TOKEN,
    "admin": ADMIN_TOKEN,
}


@pytest.fixture
def server(tmp_path):
    instance = api.make_server(
        str(tmp_path / "auth-ledger.db"), port=0, role_tokens=ROLE_TOKENS
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{instance.server_address[1]}"
    instance.shutdown()
    instance.server_close()
    thread.join(timeout=2)


def request(base, method, path, role_token=None, body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if role_token is not None:
        headers["Authorization"] = f"Bearer {role_token}"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = response.read()
            if "application/json" in response.headers.get("Content-Type", ""):
                payload = json.loads(payload)
            return response.status, payload
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def test_data_routes_require_valid_credentials(server):
    assert request(server, "GET", "/events")[0] == 401
    assert request(server, "GET", "/events", "incorrect")[0] == 401
    assert request(server, "GET", "/stream?token=" + VIEWER_TOKEN)[0] == 401
    assert request(server, "GET", "/verify")[0] == 200
    assert request(server, "POST", "/inbound", body={})[0] == 401
    assert request(server, "POST", "/inbound", "incorrect", {})[0] == 401


def test_each_role_is_limited_to_its_routes(server):
    assert request(server, "GET", "/whoami", AGENT_TOKEN) == (200, {"role": "agent"})
    assert request(server, "GET", "/events", AGENT_TOKEN)[0] == 403
    assert request(server, "POST", "/inbound", VIEWER_TOKEN, {})[0] == 403
    assert request(server, "POST", "/override", VIEWER_TOKEN, {})[0] == 403

    assert request(server, "GET", "/events", VIEWER_TOKEN) == (200, [])
    assert request(server, "POST", "/inbound", AGENT_TOKEN, {
        "session_id": "role-test", "source": "sms", "content": "hello",
    })[0] == 200
    assert request(server, "POST", "/override", APPROVER_TOKEN, {})[0] == 400


def test_admin_can_access_all_data_routes(server):
    assert request(server, "GET", "/whoami", ADMIN_TOKEN) == (200, {"role": "admin"})
    assert request(server, "GET", "/events", ADMIN_TOKEN) == (200, [])
    assert request(server, "POST", "/outbound", ADMIN_TOKEN, {
        "session_id": "admin-test", "recipient": "daughter@example.com",
        "channel": "email", "content": "hello",
    })[0] == 200
    assert request(server, "POST", "/override", ADMIN_TOKEN, {})[0] == 400


def test_http_guard_sends_the_agent_credential_for_wall_requests(server):
    client = HttpGuard(server, token=AGENT_TOKEN)
    inbound = client.inbound("agent-session", "sms", "Please review this")
    assert inbound["tainted"] is True
    outbound = client.outbound(
        "clean-session", "daughter@example.com", "email", "The payment is on hold."
    )
    assert outbound["decision"] == "allow"


@pytest.mark.parametrize("role_tokens", [
    {"viewer": VIEWER_TOKEN, "approver": APPROVER_TOKEN},
    {"agent": "short", "viewer": VIEWER_TOKEN, "approver": APPROVER_TOKEN},
    {"agent": AGENT_TOKEN, "viewer": VIEWER_TOKEN, "approver": VIEWER_TOKEN},
])
def test_credentials_must_be_complete_strong_and_distinct(tmp_path, role_tokens):
    with pytest.raises(ValueError):
        api.make_server(str(tmp_path / "invalid.db"), role_tokens=role_tokens)


def test_missing_credentials_name_environment_variables_and_generation_command(tmp_path):
    with pytest.raises(ValueError) as exc_info:
        api.make_server(str(tmp_path / "missing.db"), role_tokens={})
    message = str(exc_info.value)
    assert "ACCRUE_AGENT_TOKEN" in message
    assert "ACCRUE_VIEWER_TOKEN" in message
    assert "ACCRUE_APPROVER_TOKEN" in message
    assert "ACCRUE_DASHBOARD_TOKEN" in message
    assert "python3 -c 'import secrets; print(secrets.token_urlsafe(24))'" in message


def test_public_dashboard_and_cors_preflight(server):
    status, body = request(server, "GET", "/")
    assert status == 200 and body is not None
    req = urllib.request.Request(server + "/stream", method="OPTIONS", headers={
        "Access-Control-Request-Headers": "Authorization, Last-Event-ID",
    })
    with urllib.request.urlopen(req, timeout=5) as response:
        assert response.status == 204
        assert "Last-Event-ID" in response.headers["Access-Control-Allow-Headers"]
    assert request(server, "GET", "/limits")[0] == 200
