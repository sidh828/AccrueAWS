"""Signed delegation tokens (guard/tokens.py): a sub-agent's budget and
tools can only shrink, the chain is proven rather than claimed, and a
forged or altered token is refused - through the guard and over HTTP."""

import base64
import json
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest

from guard import api, authorize, explain, ledger, tokens

KEY = "test-token-key-held-by-the-guard"


# --- The token itself ------------------------------------------------------------

def test_a_minted_token_says_who_and_how_much():
    token = tokens.mint(KEY, "mom", agent="bills-agent", day_cents=50_000,
                        tools=["pay_bill", "buy_gift_card"])
    d = tokens.verify(KEY, token)
    assert d.chain == ("mom", "bills-agent")
    assert d.budgets == ((1, 50_000),)
    assert d.tools == {"pay_bill", "buy_gift_card"}


def test_a_child_narrows_its_parents_token_without_the_key():
    parent = tokens.mint(KEY, "mom", agent="bills-agent", day_cents=50_000)
    child = tokens.attenuate(parent, {"agent": "giftcard-subagent"})
    child = tokens.attenuate(child, {"day_cents": 10_000})
    child = tokens.attenuate(child, {"tools": ["buy_gift_card"]})
    d = tokens.verify(KEY, child)
    assert d.chain == ("mom", "bills-agent", "giftcard-subagent")
    assert d.budgets == ((1, 50_000), (2, 10_000))
    assert d.tools == {"buy_gift_card"}


def _rewrite(token, change):
    body = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
    change(body["caveats"])
    raw = json.dumps(body, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.mark.parametrize("forgery", [
    "raise the budget", "drop a caveat", "reorder caveats", "rename the agent",
    "switch the person"])
def test_editing_a_token_breaks_its_signature(forgery):
    """A sub-agent "forges a bigger budget" (the plan's proof), or quietly
    drops the caveat that names it: rejected."""
    child = tokens.attenuate(tokens.mint(KEY, "mom", agent="bills-agent", day_cents=50_000),
                             {"day_cents": 10_000})
    edit = {
        "raise the budget": lambda c: c[-1].update(day_cents=900_000),
        "drop a caveat": lambda c: c.pop(),
        "reorder caveats": lambda c: c.reverse(),
        "rename the agent": lambda c: c[1].update(agent="trusted-agent"),
        "switch the person": lambda c: c[0].update(person="dad"),
    }[forgery]
    with pytest.raises(tokens.TokenError):
        tokens.verify(KEY, _rewrite(child, edit))


def test_a_token_signed_with_another_key_is_refused():
    with pytest.raises(tokens.TokenError, match="signature"):
        tokens.verify(KEY, tokens.mint("someone-elses-key", "mom", agent="bills-agent"))


def test_only_the_guard_mints_a_root():
    token = tokens.mint(KEY, "mom", agent="bills-agent")
    with pytest.raises(tokens.TokenError, match="only the guard"):
        tokens.attenuate(token, {"person": "dad"})


def test_an_expired_token_is_refused():
    token = tokens.attenuate(tokens.mint(KEY, "mom", agent="bills-agent"),
                             {"expires": "2026-10-24T18:00:00.000000Z"})
    assert tokens.verify(KEY, token, "2026-10-24T17:59:59.000000Z").chain[1] == "bills-agent"
    with pytest.raises(tokens.TokenError, match="expired"):
        tokens.verify(KEY, token, "2026-10-24T18:00:00.000000Z")


@pytest.mark.parametrize("junk", ["", "not-base64!!", base64.urlsafe_b64encode(b"[]").decode(),
                                  tokens.mint(KEY, "mom")[:-4]])
def test_garbage_is_refused(junk):
    with pytest.raises(tokens.TokenError):
        tokens.verify(KEY, junk)


# --- Enforced by the guard ---------------------------------------------------------

TOOL = {"gift_card": "buy_gift_card", "transfer": "send_zelle"}


@pytest.fixture
def conn():
    c = ledger.connect(":memory:")
    long_ago = datetime.now(timezone.utc) - timedelta(days=60)
    for payee, category in [("kroger.example", "groceries"), ("giftcards.example", "gift_card"),
                            ("grandson.example", "transfer")]:
        ledger.insert_event(c, ledger.utc_timestamp(long_ago), "s0", "pay", payee, 100, "ALLOW",
                            scope_id="mom/bills-agent", payee=payee, category=category)
    c.commit()
    return c


def pay(conn, token, amount, payee="grandson.example", category="transfer", tool=None):
    d = tokens.verify(KEY, token)
    return authorize.authorize_payment(
        conn, person="mom", chain=list(d.chain), tool=tool or TOOL.get(category, "pay_bill"),
        amount_cents=amount, payee=payee, category=category, session_id="s", delegation=d)


@pytest.mark.cedar
def test_a_sub_agent_cannot_spend_past_its_own_budget(conn):
    parent = tokens.mint(KEY, "mom", agent="bills-agent", day_cents=50_000)
    child = tokens.attenuate(tokens.attenuate(parent, {"agent": "zelle-subagent"}),
                             {"day_cents": 30_000})
    assert pay(conn, child, 20_000)["decision"] == "allow"
    response = pay(conn, child, 15_000)
    assert (response["decision"], response["rule"]) == ("deny", "delegation_budget")
    event = ledger.get_event(conn, response["event_id"])
    assert explain.template(event) == (
        "Stopped: zelle-subagent has $100.00 left of the budget it was given for 24 hours, "
        "and asked for $150.00.")
    assert explain.check(explain.template(event), event)


@pytest.mark.cedar
def test_a_bigger_budget_added_by_the_child_changes_nothing(conn):
    """The tightest caveat wins: a sub-agent writing itself a $9,000 budget
    under a $300 parent still stops at $300."""
    parent = tokens.mint(KEY, "mom", agent="bills-agent", day_cents=30_000)
    greedy = tokens.attenuate(tokens.attenuate(parent, {"agent": "greedy-subagent"}),
                              {"day_cents": 900_000})
    assert pay(conn, greedy, 25_000)["decision"] == "allow"
    assert pay(conn, greedy, 10_000)["rule"] == "delegation_budget"


@pytest.mark.cedar
def test_sibling_sub_agents_share_their_parents_budget(conn):
    """The plan's 'two sub-agents at $300 each' under a parent allowed
    $400: the second one doesn't fit, whichever asks first."""
    parent = tokens.mint(KEY, "mom", agent="bills-agent", day_cents=40_000)
    a = tokens.attenuate(parent, {"agent": "sub-a"})
    b = tokens.attenuate(parent, {"agent": "sub-b"})
    assert pay(conn, a, 30_000)["decision"] == "allow"
    assert pay(conn, b, 30_000)["rule"] == "delegation_budget"


@pytest.mark.cedar
def test_a_sub_agent_cannot_use_a_tool_it_was_not_given(conn):
    gifts_only = tokens.attenuate(
        tokens.attenuate(tokens.mint(KEY, "mom", agent="bills-agent"),
                         {"agent": "giftcard-subagent"}),
        {"tools": ["buy_gift_card"]})
    assert pay(conn, gifts_only, 2_500, "giftcards.example", "gift_card")["decision"] == "allow"
    response = pay(conn, gifts_only, 2_500)
    assert (response["decision"], response["rule"]) == ("deny", "delegation_tool")
    assert explain.template(ledger.get_event(conn, response["event_id"])) == (
        "Stopped: giftcard-subagent wasn't given the send_zelle tool, so it can't pay "
        "$25.00 to grandson.example.")


@pytest.mark.cedar
def test_the_request_chain_must_match_the_token(conn):
    d = tokens.verify(KEY, tokens.mint(KEY, "mom", agent="bills-agent"))
    with pytest.raises(ValueError, match="issued to"):
        authorize.authorize_payment(
            conn, person="mom", chain=["mom", "trusted-agent"], tool="pay_bill",
            amount_cents=100, payee="kroger.example", category="groceries", session_id="s",
            delegation=d)


# --- Over HTTP -----------------------------------------------------------------------

AGENT_API_TOKEN = "agent-api-" + "a" * 40
ROLE_TOKENS = {
    "agent": AGENT_API_TOKEN,
    "viewer": "viewer-" + "v" * 40,
    "approver": "approver-" + "p" * 40,
}


@pytest.fixture
def server(tmp_path):
    srv = api.make_server(str(tmp_path / "ledger.db"), port=0, role_tokens=ROLE_TOKENS,
                          token_key=KEY, require_token=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def post(base, body):
    req = urllib.request.Request(base + "/authorize", json.dumps(body).encode(),
                                 {"Content-Type": "application/json",
                                  "Authorization": f"Bearer {AGENT_API_TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


@pytest.mark.cedar
def test_over_http_the_token_decides_the_chain(server):
    """The agent's bare chain is ignored once tokens are on: a sub-agent
    claiming to be the trusted bills agent is logged as what its token
    proves it is."""
    child = tokens.attenuate(tokens.mint(KEY, "mom", agent="bills-agent"),
                             {"agent": "giftcard-subagent"})
    body = {"person": "mom", "chain": ["mom", "bills-agent"], "token": child,
            "tool": "buy_gift_card", "amount_cents": 2_500, "payee": "giftcards.example",
            "category": "gift_card", "session_id": "s"}
    status, answer = post(server, body)
    assert status == 200
    viewer_headers = {"Authorization": "Bearer " + ROLE_TOKENS["viewer"]}
    with urllib.request.urlopen(urllib.request.Request(
            server + "/events", headers=viewer_headers), timeout=10) as r:
        [row] = json.loads(r.read())
    assert row["chain"] == ["mom", "bills-agent", "giftcard-subagent"]


@pytest.mark.cedar
def test_over_http_a_forged_or_missing_token_is_refused(server):
    """The plan's 'sub-agent fakes or drops its chain': refused, not paid."""
    base = {"person": "mom", "chain": ["mom", "bills-agent"], "tool": "pay_bill",
            "amount_cents": 100, "payee": "kroger.example", "category": "groceries",
            "session_id": "s"}
    forged = _rewrite(tokens.mint(KEY, "mom", agent="bills-agent", day_cents=100),
                      lambda c: c[-1].update(day_cents=900_000))
    assert post(server, {**base, "token": forged})[0] == 401
    assert post(server, base)[0] == 401
    viewer_headers = {"Authorization": "Bearer " + ROLE_TOKENS["viewer"]}
    with urllib.request.urlopen(urllib.request.Request(
            server + "/events", headers=viewer_headers), timeout=10) as r:
        assert json.loads(r.read()) == []
