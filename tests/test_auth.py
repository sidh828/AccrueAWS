"""Role-based API authentication; these routes do not need Cedar."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from guard import api
from agent.tools import HttpGuard

TOKENS = {
    "agent": "auth-agent-" + "a" * 40,
    "viewer": "auth-viewer-" + "v" * 40,
    "approver": "auth-approver-" + "p" * 40,
    "admin": "auth-admin-" + "d" * 40,
}


@pytest.fixture
def server(tmp_path):
    srv = api.make_server(str(tmp_path / "ledger.db"), port=0, role_tokens=TOKENS)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def call(base, method, path, role=None, body=None):
    data = None if body is None else json.dumps(body).encode()
    headers = {}
    if role:
        headers["Authorization"] = f"Bearer {TOKENS[role]}"
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as res:
            content = res.read()
            try:
                payload = json.loads(content)
            except json.JSONDecodeError:
                payload = content
            return res.status, payload
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_authentication_is_required_for_api_data_but_not_dashboard_assets(server):
    assert call(server, "GET", "/events")[0] == 401
    assert call(server, "GET", "/whoami")[0] == 401
    assert call(server, "POST", "/inbound", body={
        "session_id": "auth-test", "source": "sms", "content": "hello",
    })[0] == 401
    assert call(server, "GET", "/")[0] == 200
    assert call(server, "GET", "/app.js")[0] == 200


def test_roles_only_access_their_permitted_routes(server):
    for role in TOKENS:
        assert call(server, "GET", "/whoami", role=role) == (
            200, {"role": role})

    assert call(server, "GET", "/events", role="agent")[0] == 403
    assert call(server, "GET", "/limits", role="viewer")[0] == 200
    assert call(server, "GET", "/limits", role="approver")[0] == 200
    assert call(server, "GET", "/limits", role="admin")[0] == 200
    assert call(server, "POST", "/inbound", role="viewer", body={
        "session_id": "auth-test", "source": "sms", "content": "hello",
    })[0] == 403
    assert call(server, "POST", "/inbound", role="approver", body={
        "session_id": "auth-test", "source": "sms", "content": "hello",
    })[0] == 403
    assert call(server, "POST", "/inbound", role="agent", body={
        "session_id": "auth-test", "source": "sms", "content": "hello",
    })[0] == 200
    assert call(server, "POST", "/inbound", role="admin", body={
        "session_id": "auth-test", "source": "sms", "content": "hello",
    })[0] == 200
    outbound = {
        "session_id": "auth-test", "recipient": "family@example.com",
        "channel": "email", "content": "hello",
    }
    assert call(server, "POST", "/outbound", role="viewer", body=outbound)[0] == 403
    assert call(server, "POST", "/outbound", role="agent", body=outbound)[0] == 200


def test_only_approver_and_admin_reach_override_validation(server):
    for role in ("agent", "viewer"):
        assert call(server, "POST", "/override", role=role, body={})[0] == 403
    for role in ("approver", "admin"):
        assert call(server, "POST", "/override", role=role, body={})[0] == 400


def test_agent_and_admin_can_reach_authorization_validation(server):
    assert call(server, "POST", "/authorize", role="viewer", body={})[0] == 403
    assert call(server, "POST", "/authorize", role="agent", body={})[0] == 400
    assert call(server, "POST", "/authorize", role="admin", body={})[0] == 400


def test_http_guard_uses_the_agent_environment_credential(server, monkeypatch):
    monkeypatch.setenv("ACCRUE_AGENT_TOKEN", TOKENS["agent"])
    result = HttpGuard(server).inbound("agent-session", "sms", "hello")
    assert result["tainted"] is True


def test_server_loads_role_credentials_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("ACCRUE_AGENT_TOKEN", TOKENS["agent"])
    monkeypatch.setenv("ACCRUE_VIEWER_TOKEN", TOKENS["viewer"])
    monkeypatch.delenv("ACCRUE_APPROVER_TOKEN", raising=False)
    monkeypatch.setenv("ACCRUE_DASHBOARD_TOKEN", TOKENS["approver"])
    monkeypatch.delenv("ACCRUE_ADMIN_TOKEN", raising=False)
    srv = api.make_server(str(tmp_path / "environment.db"))
    try:
        assert srv.RequestHandlerClass.role_tokens == {
            "agent": TOKENS["agent"],
            "viewer": TOKENS["viewer"],
            "approver": TOKENS["approver"],
        }
    finally:
        srv.server_close()


@pytest.mark.parametrize("tokens", [
    {"viewer": TOKENS["viewer"], "approver": TOKENS["approver"]},
    {"agent": "short", "viewer": TOKENS["viewer"], "approver": TOKENS["approver"]},
    {"agent": TOKENS["agent"], "viewer": TOKENS["viewer"], "approver": TOKENS["viewer"]},
    {"agent": TOKENS["agent"], "viewer": TOKENS["viewer"], "approver": TOKENS["approver"],
     "unexpected": "x" * 40},
])
def test_server_requires_complete_strong_distinct_known_role_credentials(tmp_path, tokens):
    with pytest.raises(ValueError):
        api.make_server(str(tmp_path / "invalid.db"), role_tokens=tokens)
