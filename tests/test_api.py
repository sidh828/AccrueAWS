"""guard/api.py over HTTP, against a real ledger file and the real Cedar
CLI: the contract's shapes, the dashboard's token, folding approvals into
the payment they settle, failing closed, the live stream, /verify, and
fifty payments fired at once over the network.
"""

import http.client
import json
import threading
import urllib.error
import urllib.request

import pytest

from guard import api, ledger

pytestmark = pytest.mark.cedar

TOKEN = "test-dashboard-token"
CONTRACT_FIELDS = {
    "event_id", "ts", "status", "person", "chain", "tool", "amount_cents", "payee",
    "category", "decision", "rule", "explanation", "flagged", "row_hash",
}


class Sessions:
    """A stand-in taint store: anything with is_tainted(session_id)."""

    def __init__(self, tainted=()):
        self.tainted = set(tainted)

    def is_tainted(self, session_id):
        return session_id in self.tainted


@pytest.fixture
def guard(tmp_path):
    sessions = Sessions()
    db_path = str(tmp_path / "ledger.db")
    server = api.make_server(db_path, TOKEN, port=0, sessions=sessions)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    yield {"base": base, "db": db_path, "sessions": sessions}
    server.shutdown()
    server.server_close()


def call(guard, method, path, body=None, token=None, content_type="application/json"):
    data = None if body is None else (
        body if isinstance(body, bytes) else json.dumps(body).encode())
    request = urllib.request.Request(guard["base"] + path, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", content_type)
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def pay(guard, amount, payee="grocer.example", category="groceries", **extra):
    body = {"person": "mom", "chain": ["mom", "bills-agent"], "tool": "pay_bill",
            "amount_cents": amount, "payee": payee, "category": category,
            "session_id": "sess-1", "reason": "test", **extra}
    return call(guard, "POST", "/authorize", body)


def known_payee(guard, payee="grocer.example", category="groceries"):
    """A payment 60 days ago, so `payee` is someone Margaret has paid for a
    while (not new, not recent) and today starts at $0."""
    from datetime import datetime, timedelta, timezone
    conn = ledger.connect(guard["db"])
    ledger.insert_event(
        conn, ledger.utc_timestamp(datetime.now(timezone.utc) - timedelta(days=60)),
        "sess-0", "pay", payee, 100, "ALLOW", scope_id="mom/bills-agent",
        payee=payee, category=category,
    )
    conn.commit()
    conn.close()


def test_authorize_answers_in_the_contract_shape(guard):
    known_payee(guard)
    status, body = pay(guard, 12_000, request_id="req-1")
    assert status == 200
    assert body == {"decision": "allow", "rule": None,
                    "totals": {"day": 12_000, "gift_card_day": 0, "recent_payees": 0},
                    "limits": {"day": 50_000, "gift_card_day": 10_000, "new_payee_first": 20_000,
                               "recent_payees": 50_000},
                    "needs_approval": False, "event_id": 2}
    assert pay(guard, 12_000, request_id="req-1") == (200, body)  # a retry, not a new payment

    status, rows = call(guard, "GET", "/events?since=1")
    assert status == 200 and len(rows) == 1
    assert set(rows[0]) == CONTRACT_FIELDS | {"resolved_by", "notice", "known_bill"}
    assert rows[0]["status"] == "allowed" and rows[0]["ts"].endswith("Z")


def test_bad_requests_are_refused_and_not_logged(guard):
    assert pay(guard, 1_000, chain=["dad", "bills-agent"])[0] == 400
    assert pay(guard, 10.5)[0] == 400
    assert call(guard, "POST", "/authorize", {"person": "mom"})[0] == 400
    assert call(guard, "POST", "/authorize", b"not json")[0] == 400
    assert call(guard, "POST", "/authorize", b"{}", content_type="text/plain")[0] == 415
    assert call(guard, "GET", "/events")[1] == []


def test_a_tainted_session_gets_the_stricter_rules_whatever_the_request_says(guard):
    known_payee(guard, "giftcards.example", "gift_card")
    guard["sessions"].tainted.add("sess-1")
    status, body = pay(guard, 5_000, "giftcards.example", "gift_card", tainted=False)
    assert (body["decision"], body["rule"]) == ("hold", "gift_card_needs_approval")
    assert body["limits"]["day"] == 10_000


def test_a_request_can_taint_itself_but_never_untaint(guard):
    known_payee(guard, "giftcards.example", "gift_card")
    _, body = pay(guard, 5_000, "giftcards.example", "gift_card", tainted=True)
    assert body["decision"] == "hold"


def test_override_needs_the_dashboards_token_and_json(guard):
    known_payee(guard)
    _, held = pay(guard, 5_000, "zelle:new-contact", "transfer", tainted=True)
    assert held["decision"] == "hold"
    approve = {"event_id": held["event_id"], "action": "approve"}

    assert call(guard, "POST", "/override", approve)[0] == 401
    assert call(guard, "POST", "/override", approve, token="wrong")[0] == 401
    assert call(guard, "POST", "/override", json.dumps(approve).encode(), token=TOKEN,
                content_type="text/plain")[0] == 415
    # Still waiting after all of that.
    _, rows = call(guard, "GET", "/events")
    assert rows[-1]["status"] == "held"


def test_an_approval_settles_the_payment_it_resolves(guard):
    """The ledger appends a row that resolves the hold; the dashboard sees
    the held payment itself become allowed - once, under its own id, so
    the running total counts it once."""
    known_payee(guard)
    _, held = pay(guard, 5_000, "zelle:new-contact", "transfer", tainted=True)
    status, view = call(guard, "POST", "/override",
                        {"event_id": held["event_id"], "action": "approve"}, token=TOKEN)
    assert status == 200
    assert view["event_id"] == held["event_id"]
    assert (view["decision"], view["status"], view["rule"]) == (
        "allow", "allowed", "approved_by_family")
    assert view["resolved_by"] == held["event_id"] + 1

    _, rows = call(guard, "GET", "/events?since=1")
    assert [(r["event_id"], r["status"]) for r in rows] == [(held["event_id"], "allowed")]
    # Polling from after the hold still picks up its approval.
    _, rows = call(guard, "GET", f"/events?since={held['event_id']}")
    assert [(r["event_id"], r["status"]) for r in rows] == [(held["event_id"], "allowed")]

    # Approved with the family's OK, so it doesn't use up the day: the full
    # $500 is still there for groceries, and past it a payment to someone
    # she's paid before waits for the family.
    assert pay(guard, 50_000)[1]["decision"] == "allow"
    assert pay(guard, 1)[1]["rule"] == "daily_cap_needs_approval"

    assert call(guard, "POST", "/override",
                {"event_id": held["event_id"], "action": "deny"}, token=TOKEN)[0] == 409
    assert call(guard, "POST", "/override",
                {"event_id": 999, "action": "deny"}, token=TOKEN)[0] == 404


def test_a_broken_rules_engine_holds(guard, monkeypatch, tmp_path):
    from guard import authorize
    monkeypatch.setattr(authorize, "CEDAR_BIN", str(tmp_path / "no-such-cedar"))
    known_payee(guard)
    status, body = pay(guard, 1_000)
    assert status == 200
    assert (body["decision"], body["rule"]) == ("hold", "guard_unavailable")


def test_a_broken_ledger_answers_hold_not_allow(tmp_path):
    server = api.make_server(str(tmp_path / "ledger.db"), TOKEN, port=0)
    server.RequestHandlerClass.db_path = str(tmp_path / "missing-dir" / "ledger.db")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        g = {"base": f"http://127.0.0.1:{server.server_address[1]}"}
        status, body = pay(g, 1_000)
        assert status == 503
        assert (body["decision"], body["rule"], body["needs_approval"]) == (
            "hold", "guard_unavailable", True)
    finally:
        server.shutdown()
        server.server_close()


def test_the_stream_sends_new_payments_and_settled_ones(guard):
    known_payee(guard)
    host, port = guard["base"].removeprefix("http://").split(":")
    stream = http.client.HTTPConnection(host, int(port), timeout=10)
    stream.request("GET", "/stream", headers={"Last-Event-ID": "1"})
    response = stream.getresponse()
    assert response.status == 200
    assert response.getheader("Content-Type") == "text/event-stream"

    def next_event():
        lines = []
        while True:
            line = response.fp.readline().decode().rstrip("\n")
            if line == "" and lines:
                return lines
            if line and not line.startswith(":"):
                lines.append(line)

    _, held = pay(guard, 5_000, "zelle:new-contact", "transfer", tainted=True)
    event = next_event()
    assert event[0] == f"id: {held['event_id']}"
    assert json.loads(event[1].removeprefix("data: "))["status"] == "held"

    call(guard, "POST", "/override", {"event_id": held["event_id"], "action": "deny"}, token=TOKEN)
    event = next_event()
    assert len(event) == 1  # no id line: an old payment, settled
    settled = json.loads(event[0].removeprefix("data: "))
    assert (settled["event_id"], settled["status"]) == (held["event_id"], "released")
    stream.close()


def test_verify_and_limits(guard):
    known_payee(guard)
    pay(guard, 1_000)
    status, result = call(guard, "GET", "/verify")
    assert status == 200 and result["ok"] is True
    head = result["head"]
    status, anchored = call(
        guard, "GET", f"/verify?anchor_id={head['event_id']}&anchor_hash={head['row_hash']}")
    assert anchored["ok"] is True
    assert call(guard, "GET", f"/verify?anchor_id={head['event_id']}&anchor_hash=0")[1]["ok"] is False
    assert call(guard, "GET", "/verify?anchor_id=x")[0] == 400

    conn = ledger.connect(guard["db"])
    conn.execute("DROP TRIGGER prevent_event_updates")
    conn.execute("UPDATE events SET amount_cents = 0 WHERE id = 2")
    conn.commit()
    assert call(guard, "GET", "/verify")[1]["first_bad_event_id"] == 2

    status, limits = call(guard, "GET", "/limits")
    assert status == 200
    assert limits["normal"]["day"] == 50_000 and limits["flagged"]["day"] == 10_000
    assert limits["normal"]["recent_payees"] == 50_000


def test_the_dashboard_is_served(guard):
    with urllib.request.urlopen(guard["base"] + "/", timeout=10) as response:
        assert response.status == 200 and b"<" in response.read()
    with urllib.request.urlopen(guard["base"] + "/app.js", timeout=10) as response:
        assert response.status == 200


def test_fifty_payments_at_once_over_http_land_on_the_cap(guard):
    """The proof-panel demo end to end: fifty $50 payments fired at the API
    at once. Exactly $500 is allowed."""
    known_payee(guard)
    results = []
    threads = [threading.Thread(target=lambda: results.append(pay(guard, 5_000)))
               for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert all(status == 200 for status, _ in results)
    assert [body["decision"] for _, body in results].count("allow") == 10
    _, rows = call(guard, "GET", "/events?since=1")
    assert sum(r["amount_cents"] for r in rows if r["decision"] == "allow") == 50_000
