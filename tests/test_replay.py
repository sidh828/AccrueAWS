"""Policy replay (guard/replay.py): a draft rule run against real history -
Margaret's simulated September - before it goes live."""

import json
import threading
import urllib.error
import urllib.request

import pytest

from guard import api, authorize, ledger, replay, sim

pytestmark = pytest.mark.cedar

SEPTEMBER = "2026-09-01T00:00:00.000000Z"
LIVE = authorize.FAMILY_POLICY_PATH.read_text()


@pytest.fixture(scope="module")
def september(tmp_path_factory):
    """Margaret's September with every scam in it, as a ledger file."""
    path = str(tmp_path_factory.mktemp("replay") / "ledger.db")
    sim.run(ledger.connect(path))
    return path


def test_the_live_policy_changes_nothing(september):
    result = replay.replay(ledger.connect(september), LIVE, since=SEPTEMBER)
    assert result["checked"] > 50
    assert result["changes"] == []


def test_a_stricter_draft_shows_what_it_would_have_stopped(september):
    """"No gift cards at all": the grandson's birthday card would have been
    stopped too - the family sees that before they turn it on."""
    draft = LIVE + '''
@id("no_gift_cards")
forbid (principal, action == Action::"pay", resource)
when { context.is_gift_card };
'''
    result = replay.replay(ledger.connect(september), draft, since=SEPTEMBER)
    newly = [c for c in result["changes"] if c["before"]["decision"] != c["after"]["decision"]]
    assert result["summary"]["newly_stopped"] == len(newly) > 0
    assert all(c["category"] == "gift_card" and c["after"] == {
        "decision": "deny", "rule": "no_gift_cards"} for c in newly)
    assert any(c["payee"] == "giftcards.example" and c["amount_cents"] == 5_000 for c in newly)


def test_a_draft_rule_can_hold_instead_of_deny(september):
    """@outcome("hold") makes a new rule wait for the family instead of
    stopping: with "every gift card needs your OK", the grandson's $50
    birthday card would have waited rather than gone through."""
    draft = LIVE + '''
@id("gift_cards_need_approval")
@outcome("hold")
forbid (principal, action == Action::"pay", resource)
when { context.is_gift_card };
'''
    result = replay.replay(ledger.connect(september), draft, since=SEPTEMBER)
    birthday = [c for c in result["changes"] if c["amount_cents"] == 5_000
                and c["payee"] == "giftcards.example"]
    assert birthday and birthday[0]["before"]["decision"] == "allow"
    assert birthday[0]["after"] == {"decision": "hold", "rule": "gift_cards_need_approval"}
    assert result["summary"]["newly_held"] >= 1


def test_a_draft_that_changes_nothing_says_so(september):
    """In the month with every scam, each bitcoin-ATM payment was already
    stopped or held by another rule, so "crypto needs approval" would have
    changed nothing - and replay says exactly that."""
    draft = LIVE + '''
@id("crypto_needs_approval")
@outcome("hold")
forbid (principal, action == Action::"pay", resource)
when { context.tool == "send_crypto" };
'''
    result = replay.replay(ledger.connect(september), draft, since=SEPTEMBER)
    assert [c for c in result["changes"] if c["payee"] == "coinflip-bitcoin-atm.example"] == []


def test_a_looser_draft_shows_what_it_would_have_let_through(september):
    """Raising the daily limit to $1,000: the payments the $500 line held
    for the family would have gone straight through."""
    draft = LIVE.replace("context.limits.day)", "100000)")
    assert draft != LIVE
    result = replay.replay(ledger.connect(september), draft, since=SEPTEMBER)
    assert result["summary"]["newly_allowed"] > 0
    assert all(c["before"]["rule"] in ("daily_cap", "daily_cap_needs_approval")
               for c in result["changes"] if c["after"]["decision"] == "allow")


def test_an_invalid_draft_is_refused(september):
    with pytest.raises(replay.DraftError):
        replay.replay(ledger.connect(september), LIVE + "\nforbid (principal) when { context.nope };",
                      since=SEPTEMBER)


def test_the_window_limits_what_is_replayed(september):
    conn = ledger.connect(september)
    everything = replay.replay(conn, LIVE, since=SEPTEMBER)["checked"]
    last_week = replay.replay(conn, LIVE, since="2026-09-24T00:00:00.000000Z")["checked"]
    assert 0 < last_week < everything


def test_rows_logged_before_newer_fields_still_replay():
    """A decision logged before the guard knew about recent payees or
    delegation tokens has no such fields; they're filled the way the guard
    behaved then, and the replay runs."""
    conn = ledger.connect(":memory:")
    context = {"person": "mom", "payee": "kroger.example", "amount": 1_000,
               "is_gift_card": False, "tainted": False, "day_total": 1_000,
               "gift_card_day_total": 0, "new_payee": False, "known_bill": False,
               "last_bill": 0, "recent_denials": 0,
               "limits": {k: v for k, v in authorize.FAMILY_LIMITS.items()
                          if not k.startswith("recent")}}
    ledger.insert_event(conn, SEPTEMBER, "s", "pay", "kroger.example", 1_000, "ALLOW",
                        scope_id="mom/bills-agent", payee="kroger.example",
                        category="groceries", tool="pay_bill", context=context)
    conn.commit()
    assert replay.replay(conn, LIVE, since=SEPTEMBER) == {
        "checked": 1, "changes": [],
        "summary": {"newly_stopped": 0, "newly_held": 0, "newly_allowed": 0}}


def test_over_http_replay_needs_the_approver_credential(september):
    approver_token = "approver-" + "p" * 40
    role_tokens = {
        "agent": "agent-" + "a" * 40,
        "viewer": "viewer-" + "v" * 40,
        "approver": approver_token,
    }
    server = api.make_server(september, port=0, role_tokens=role_tokens)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    def post(body, token=None):
        req = urllib.request.Request(base + "/replay", json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as err:
            return err.code, json.loads(err.read())

    try:
        assert post({"policy": LIVE})[0] == 401
        status, result = post({"policy": LIVE, "since": SEPTEMBER}, token=approver_token)
        assert status == 200 and result["changes"] == []
        status, err = post({"policy": "nonsense", "since": SEPTEMBER}, token=approver_token)
        assert status == 400 and "isn't valid" in err["error"]
    finally:
        server.shutdown()
        server.server_close()
