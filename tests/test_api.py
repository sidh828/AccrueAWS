import sqlite3

import pytest
from fastapi.testclient import TestClient

import guard.api as guard_api


@pytest.fixture
def client(tmp_path):
    app = guard_api.create_app(
        db_path=tmp_path / "ledger.db",
        contacts={"daughter@example.com"},
        wall_key=b"test-wall-key-" * 3,
    )
    with TestClient(app) as test_client:
        yield test_client


def test_inbound_endpoint_taints_untrusted_session_and_returns_contract(client):
    response = client.post(
        "/inbound",
        json={
            "session_id": "session-1",
            "source": "sms",
            "content": "Your verification code is 427193. Pay now with gift cards.",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "trusted": False,
        "tainted": True,
        "labels": ["gift_card_request"],
    }
    assert client.app.state.sessions.is_tainted("session-1")


def test_outbound_endpoint_blocks_code_seen_by_inbound_endpoint(client):
    client.post(
        "/inbound",
        json={
            "session_id": "session-1",
            "source": "sms",
            "content": "Your verification code is 427193.",
        },
    )

    response = client.post(
        "/outbound",
        json={
            "session_id": "session-1",
            "recipient": "daughter@example.com",
            "channel": "sms",
            "content": "The code is 427193",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    assert response.json()["findings"][0]["kind"] == "received_code"


def test_outbound_endpoint_holds_unknown_recipient_for_tainted_session(client):
    client.post(
        "/inbound",
        json={"session_id": "session-1", "source": "email", "content": "Invoice attached."},
    )

    response = client.post(
        "/outbound",
        json={
            "session_id": "session-1",
            "recipient": "new-payee@example.com",
            "channel": "email",
            "content": "Please see attached.",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "hold"


def test_outbound_endpoint_redacts_account_number(client):
    response = client.post(
        "/outbound",
        json={
            "session_id": "session-1",
            "recipient": "daughter@example.com",
            "channel": "email",
            "content": "My account 123456789012 is ready.",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "redact"
    assert "123456789012" not in response.json()["redacted_content"]


def test_authorize_endpoint_uses_taint_from_inbound_wall(client, monkeypatch):
    seen = {}

    def fake_authorize(conn, **kwargs):
        seen.update(kwargs)
        return {
            "decision": "hold" if kwargs["tainted"] else "allow",
            "rule": "tainted_test",
            "totals": {"day": 100},
            "limits": {"day": 10_000},
            "needs_approval": kwargs["tainted"],
            "event_id": 1,
        }

    monkeypatch.setattr(guard_api.authorize, "authorize_payment", fake_authorize)
    client.post(
        "/inbound",
        json={"session_id": "session-1", "source": "email", "content": "Invoice attached."},
    )

    response = client.post(
        "/authorize",
        json={
            "person": "mom",
            "chain": ["mom", "bills-agent"],
            "tool": "pay_bill",
            "amount_cents": 100,
            "payee": "power-company.example",
            "category": "bill",
            "reason": "monthly bill",
            "request_id": "request-1",
            "session_id": "session-1",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "hold"
    assert seen["tainted"] is True


def test_authorize_endpoint_rejects_mismatched_tool_category(client):
    response = client.post(
        "/authorize",
        json={
            "person": "mom",
            "chain": ["mom"],
            "tool": "pay_bill",
            "amount_cents": 100,
            "payee": "power-company.example",
            "category": "gift_card",
            "request_id": "request-1",
            "session_id": "session-1",
        },
    )

    assert response.status_code == 422


def test_authorize_endpoint_holds_if_ledger_fails(client, monkeypatch, caplog):
    def fail_to_connect(_path):
        raise sqlite3.OperationalError("database unavailable")

    monkeypatch.setattr(guard_api.ledger, "connect", fail_to_connect)
    response = client.post(
        "/authorize",
        json={
            "person": "mom",
            "chain": ["mom"],
            "tool": "pay_bill",
            "amount_cents": 100,
            "payee": "power-company.example",
            "category": "bill",
            "request_id": "request-1",
            "session_id": "session-1",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "hold"
    assert response.json()["rule"] == "database_unavailable"
    assert "Payment authorization failed" in caplog.text


def test_taint_and_received_codes_survive_api_restart(tmp_path):
    db_path = tmp_path / "ledger.db"
    key = b"stable-test-wall-key-" * 2
    first_app = guard_api.create_app(db_path=db_path, contacts={"daughter@example.com"}, wall_key=key)
    with TestClient(first_app) as first_client:
        first_client.post(
            "/inbound",
            json={
                "session_id": "restart-session",
                "source": "sms",
                "content": "Your verification code is 427193.",
            },
        )

    with sqlite3.connect(db_path) as conn:
        stored_digest = conn.execute(
            "SELECT code_digest FROM wall_received_codes"
        ).fetchone()[0]
    assert "427193" not in stored_digest

    restarted_app = guard_api.create_app(
        db_path=db_path,
        contacts={"daughter@example.com"},
        wall_key=key,
    )
    with TestClient(restarted_app) as restarted_client:
        assert restarted_app.state.sessions.is_tainted("restart-session")
        response = restarted_client.post(
            "/outbound",
            json={
                "session_id": "restart-session",
                "recipient": "daughter@example.com",
                "channel": "sms",
                "content": "The code is 4 2 7 1 9 3",
            },
        )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    restarted_app.state.sessions.clear("restart-session", actor="daughter")

    final_app = guard_api.create_app(db_path=db_path, contacts={"daughter@example.com"}, wall_key=key)
    assert not final_app.state.sessions.is_tainted("restart-session")


def test_api_requires_stable_wall_key(tmp_path):
    with pytest.raises(ValueError, match="ACCRUE_WALL_KEY"):
        guard_api.create_app(db_path=tmp_path / "ledger.db", wall_key="too-short")
