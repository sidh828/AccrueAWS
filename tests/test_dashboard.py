"""The dashboard's stand-in API speaks the contract in CLAUDE.md, and phone
alerts read in plain English. CONTRACT_FIELDS is the event row from the
contract; guard/api.py's rows should pass the same check once it exists."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from dashboard import alerts, fake_api

CONTRACT_FIELDS = {
    "event_id", "ts", "status", "person", "chain", "tool", "amount_cents", "payee",
    "category", "decision", "rule", "explanation", "flagged", "row_hash",
}
DECISION_STATUS = {("allow", "allowed"), ("deny", "released"), ("hold", "held")}


@pytest.fixture
def api():
    guard = fake_api.FakeGuard()
    fake_api.play(guard, step=0)
    server = fake_api.make_server(guard, port=0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def get(url):
    with urllib.request.urlopen(url) as res:
        return json.load(res)


def post(url, body):
    request = urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request) as res:
        return json.load(res)


def test_event_rows_match_the_contract(api):
    rows = get(f"{api}/events?since=0")
    assert [r["event_id"] for r in rows] == list(range(1, len(fake_api.SCRIPT) + 1))
    for row in rows:
        assert set(row) == CONTRACT_FIELDS
        assert type(row["amount_cents"]) is int
        assert (row["decision"], row["status"]) in DECISION_STATUS
    assert [r["event_id"] for r in get(f"{api}/events?since=5")] == [6, 7]


def test_override_settles_a_held_payment_once(api):
    held = [r["event_id"] for r in get(f"{api}/events?since=0") if r["status"] == "held"]
    approved = post(f"{api}/override", {"event_id": held[0], "action": "approve"})
    assert (approved["decision"], approved["status"]) == ("allow", "allowed")
    denied = post(f"{api}/override", {"event_id": held[1], "action": "deny"})
    assert (denied["decision"], denied["status"]) == ("deny", "released")

    for body, code in [
        ({"event_id": held[0], "action": "deny"}, 409),   # already settled
        ({"event_id": 1, "action": "maybe"}, 400),
        ({"event_id": True, "action": "approve"}, 400),   # bool is not an id
        ({"event_id": 999, "action": "approve"}, 404),
    ]:
        with pytest.raises(urllib.error.HTTPError) as err:
            post(f"{api}/override", body)
        assert err.value.code == code


def test_alerts_only_for_stopped_or_held_and_in_plain_english():
    guard = fake_api.FakeGuard()
    fake_api.play(guard, step=0)
    found = [alerts.alert_for(row) for row in guard.since(0)]
    assert found[:2] == [None, None]  # allowed payments don't buzz the phone
    assert found[2]["title"] == "Stopped" and "$450 gift card" in found[2]["message"]
    assert found[-1]["title"] == "Needs your OK" and "$180 bill" in found[-1]["message"]
    for alert in filter(None, found):
        assert "cedar" not in alert["message"].lower()
        assert "ledger" not in alert["message"].lower()
