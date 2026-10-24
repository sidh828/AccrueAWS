"""The dashboard's stand-in API speaks the contract in CLAUDE.md, holds up
against odd or hostile clients, and phone alerts read in plain English and
survive a flaky push service. CONTRACT_FIELDS is the event row from the
contract; guard/api.py's rows should pass the same check once it exists."""

import contextlib
import http.client
import json
import threading
import urllib.error
import urllib.request
from urllib.parse import urlparse

import pytest

from dashboard import alerts, fake_api

CONTRACT_FIELDS = {
    "event_id", "ts", "status", "person", "chain", "tool", "amount_cents", "payee",
    "category", "decision", "rule", "explanation", "flagged", "row_hash",
}
DECISION_STATUS = {("allow", "allowed"), ("deny", "released"), ("hold", "held")}
GIFT_CARD_STOPPED = fake_api.SCRIPT[2]
TOKEN = "dashboard-test-token"


@contextlib.contextmanager
def serve(guard, **kwargs):
    server = fake_api.make_server(guard, TOKEN, port=0, **kwargs)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def played():
    guard = fake_api.FakeGuard()
    fake_api.play(guard, step=0)
    with serve(guard) as url:
        yield guard, url


@pytest.fixture
def api(played):
    return played[1]


def get(url):
    with urllib.request.urlopen(url) as res:
        return json.load(res)


def post(url, body, token=TOKEN, content_type="application/json"):
    headers = {"Content-Type": content_type}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    with urllib.request.urlopen(request) as res:
        return json.load(res)


def first_held(api):
    return next(r["event_id"] for r in get(f"{api}/events?since=0") if r["status"] == "held")


def status_of(api, event_id):
    return next(r["status"] for r in get(f"{api}/events?since=0") if r["event_id"] == event_id)


def read_events(res, count):
    """The next `count` server-sent events from an open /stream response,
    each as a dict of its fields; keepalive comments are skipped."""
    events, fields = [], {}
    while len(events) < count:
        raw = res.readline()
        assert raw, "the stream closed"
        line = raw.decode().rstrip("\n")
        if not line:
            if fields:
                events.append(fields)
            fields = {}
        elif not line.startswith(":"):
            key, _, value = line.partition(": ")
            fields[key] = value
    return events


# ---- the contract ----------------------------------------------------------

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


def test_stream_resumes_after_last_event_id_and_sends_changes_without_an_id(played):
    guard, url = played
    request = urllib.request.Request(f"{url}/stream", headers={"Last-Event-ID": "5"})
    with urllib.request.urlopen(request, timeout=5) as res:
        assert [e["id"] for e in read_events(res, 2)] == ["6", "7"]
        guard.override(6, "approve")
        [change] = read_events(res, 1)
    # An id line here would move the browser's Last-Event-ID back to 6.
    assert "id" not in change
    assert json.loads(change["data"])["status"] == "allowed"


def test_a_malformed_last_event_id_replays_from_the_start(api):
    # "²" passes str.isdigit() but int() rejects it.
    request = urllib.request.Request(f"{api}/stream", headers={"Last-Event-ID": "²"})
    with urllib.request.urlopen(request, timeout=5) as res:
        assert read_events(res, 1)[0]["id"] == "1"


# ---- hostile or odd clients -------------------------------------------------

def test_approving_needs_the_dashboard_token(api):
    held = first_held(api)
    for token in [None, "", "wrong-token", TOKEN.upper(), TOKEN + "x"]:
        with pytest.raises(urllib.error.HTTPError) as err:
            post(f"{api}/override", {"event_id": held, "action": "approve"}, token=token)
        assert err.value.code == 401
        err.value.close()
    assert status_of(api, held) == "held"


def test_a_cross_site_text_post_cannot_approve(api):
    # A web page can send a text/plain POST to any address without a CORS
    # preflight. That's how the review approved a payment from a foreign
    # origin; now it's refused, with or without the token.
    held = first_held(api)
    for token in [None, TOKEN]:
        with pytest.raises(urllib.error.HTTPError) as err:
            post(f"{api}/override", {"event_id": held, "action": "approve"},
                 token=token, content_type="text/plain")
        assert err.value.code == 415
        err.value.close()
    assert status_of(api, held) == "held"


def test_the_stand_in_needs_a_token_to_start():
    with pytest.raises(ValueError):
        fake_api.make_server(fake_api.FakeGuard(), "", port=0)


def test_only_the_dashboard_files_are_served(api):
    for path in ["/", "/index.html", "/app.js"]:
        with urllib.request.urlopen(api + path) as res:
            assert res.status == 200
    for path in ["/CLAUDE.md", "/../CLAUDE.md", "/%2e%2e/CLAUDE.md", "/fake_api.py",
                 "/dashboard/fake_api.py"]:
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(api + path)
        assert err.value.code == 404


def test_an_oversized_override_body_is_refused_unread(api):
    conn = http.client.HTTPConnection(urlparse(api).netloc, timeout=5)
    conn.putrequest("POST", "/override")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Authorization", f"Bearer {TOKEN}")
    conn.putheader("Content-Length", str(10**9))  # declared, never sent
    conn.endheaders()
    res = conn.getresponse()
    assert res.status == 413
    res.close()
    conn.close()


def test_live_streams_are_capped():
    with serve(fake_api.FakeGuard(), max_streams=1) as url:
        with urllib.request.urlopen(f"{url}/stream", timeout=5) as first:
            first.readline()  # the first stream is open and holds the only slot
            with pytest.raises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(f"{url}/stream", timeout=5)
            assert err.value.code == 503


# ---- phone alerts -----------------------------------------------------------

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


def test_an_alert_copes_with_odd_fields():
    # tool, payee and rule start out as whatever the agent sent.
    odd = {"status": "held", "tool": None, "payee": ["x"], "amount_cents": "450",
           "rule": {"not": "hashable"}, "explanation": None}
    assert alerts.alert_for(odd)["message"] == (
        "Waiting for your OK. An unknown amount payment to an unknown payee.")


def test_a_failed_push_is_kept_and_retried_with_backoff():
    guard = fake_api.FakeGuard()
    with serve(guard) as url:
        sent, up = [], [False]

        def deliver(alert):
            if up[0]:
                sent.append(alert)
            return up[0]

        watcher = alerts.Watcher(url, deliver)
        watcher.step(now=0)              # first read: nothing yet
        guard.add(*fake_api.SCRIPT[0])   # allowed: no alert
        guard.add(*GIFT_CARD_STOPPED)
        watcher.step(now=1)              # the push service is down: kept
        up[0] = True
        watcher.step(now=2)              # still backing off
        assert sent == []
        watcher.step(now=10)
        watcher.step(now=11)             # and sent once, not again
    assert [a["title"] for a in sent] == ["Stopped"]


def test_a_flood_goes_out_as_one_summary():
    guard = fake_api.FakeGuard()
    with serve(guard) as url:
        sent = []
        watcher = alerts.Watcher(url, lambda alert: sent.append(alert) or True)
        watcher.step(now=0)
        for _ in range(10):
            guard.add(*GIFT_CARD_STOPPED)
        guard.add(*fake_api.SCRIPT[-1])  # one held payment among them
        watcher.step(now=1)
    [alert] = sent
    assert alert["title"] == "Needs your OK"
    assert alert["message"].startswith("1 payment waiting for your OK and 10 payments stopped.")


def test_starting_late_still_alerts_on_payments_waiting(played):
    guard, url = played
    sent = []
    alerts.Watcher(url, lambda alert: sent.append(alert) or True).step(now=0)
    # The three stopped ones happened before we were watching; the two held
    # ones still need an answer.
    assert [a["title"] for a in sent] == ["Needs your OK", "Needs your OK"]


def test_a_row_it_cannot_read_is_skipped_not_fatal(monkeypatch, capsys):
    sent = []
    watcher = alerts.Watcher("http://unused", lambda alert: sent.append(alert) or True, replay=True)
    good = {"event_id": 3, "status": "released", "tool": "buy_gift_card",
            "amount_cents": 45000, "payee": "giftcards.example", "rule": "gift_card_daily_cap"}
    rows = [{"no": "event_id"}, "not a row", {"event_id": 7.0, "status": "held"}, good]
    monkeypatch.setattr(watcher, "_read", lambda: rows)
    watcher.step(now=0)
    assert [a["title"] for a in sent] == ["Stopped"]
    assert watcher.since == 3
    assert capsys.readouterr().out.count("skipping a row") == 3


def test_alerts_refuse_a_link_that_can_approve():
    # Alerts go through ntfy.sh, readable by anyone who knows the topic.
    with pytest.raises(SystemExit):
        alerts.main(["--dry-run", "--open", f"http://127.0.0.1:8001/#token={TOKEN}"])
