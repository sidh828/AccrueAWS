"""agent/mcp_proxy.py: Claude Desktop pays through the guard. The protocol
by itself, the things it must never do, and a real run against the guard."""

import json
import os
import subprocess
import sys
import threading
import urllib.request

import pytest

from agent import mcp_proxy
from guard import api

DASHBOARD_TOKEN = "proxy-test-dashboard-token"
AGENT_TOKEN = "agent-" + "a" * 40
VIEWER_TOKEN = "viewer-" + "v" * 40
APPROVER_TOKEN = "approver-" + "p" * 40


class FakeTools:
    """Records what the proxy asked for and answers like ToolBox."""

    def __init__(self, result):
        self.result, self.calls = result, []

    def pay_bill(self, payee, cents, reason, category="bill"):
        self.calls.append(("pay_bill", payee, cents, category))
        return self.result

    def buy_gift_card(self, payee, cents, reason):
        self.calls.append(("buy_gift_card", payee, cents))
        return self.result

    def send_zelle(self, payee, cents, reason):
        self.calls.append(("send_zelle", payee, cents))
        return self.result


def call(proxy, name, **arguments):
    response = proxy.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                             "params": {"name": name, "arguments": arguments}})
    return response["result"]


def test_it_offers_three_payment_tools_and_nothing_that_approves():
    proxy = mcp_proxy.Proxy(FakeTools({}))
    init = proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {"protocolVersion": "2025-06-18"}})
    assert init["result"]["protocolVersion"] == "2025-06-18"
    assert init["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert proxy.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    names = [tool["name"] for tool in proxy.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
    assert names == ["pay_bill", "buy_gift_card", "send_zelle"]
    assert not any("override" in n or "approve" in n for n in names)
    assert proxy.handle({"jsonrpc": "2.0", "id": 3, "method": "override"})["error"]["code"] == -32601
    assert call(proxy, "override", event_id=1)["isError"] is True


def test_it_answers_with_the_guards_decision_in_a_sentence():
    stopped = FakeTools({"ok": False, "decision": "deny", "rule": "gift_card_daily_cap"})
    text = call(mcp_proxy.Proxy(stopped), "buy_gift_card", payee="giftcards.example",
                amount_cents=45000)["content"][0]["text"]
    assert text.startswith("Stopped: $450.00 to giftcards.example was not paid (over the gift card limit)")
    held = FakeTools({"ok": False, "decision": "hold", "rule": "new_payee_needs_approval"})
    assert call(mcp_proxy.Proxy(held), "send_zelle", payee="zelle:new", amount_cents=30000
                )["content"][0]["text"].startswith("Not paid yet: $300.00 to zelle:new is waiting")
    paid = FakeTools({"ok": True, "decision": "allow", "rule": None})
    tools = paid
    assert call(mcp_proxy.Proxy(tools), "pay_bill", payee="ohio-power.example", amount_cents=12000,
                category="utility")["content"][0]["text"] == "Paid: $120.00 to ohio-power.example."
    assert tools.calls == [("pay_bill", "ohio-power.example", 12000, "utility")]


@pytest.mark.parametrize("arguments", [
    {"payee": "x.example", "amount_cents": 450.5},   # no fractions of a cent
    {"payee": "x.example", "amount_cents": "45000"},
    {"payee": "x.example", "amount_cents": True},
    {"payee": "x.example", "amount_cents": 0},
    {"payee": "", "amount_cents": 100},
])
def test_odd_arguments_are_refused_before_the_guard_is_asked(arguments):
    tools = FakeTools({"ok": True})
    result = call(mcp_proxy.Proxy(tools), "buy_gift_card", **arguments)
    assert result["isError"] is True and result["content"][0]["text"].startswith("Not paid")
    assert tools.calls == []


def test_a_failure_inside_is_not_paid():
    class Broken(FakeTools):
        def buy_gift_card(self, *args):
            raise RuntimeError("guard went away")
    text = call(mcp_proxy.Proxy(Broken({})), "buy_gift_card", payee="g.example",
                amount_cents=100)["content"][0]["text"]
    assert text.startswith("Not paid yet") and "couldn't check" in text


def test_it_refuses_to_start_holding_the_dashboard_token():
    env = {**os.environ, "ACCRUE_DASHBOARD_TOKEN": "x"}
    proc = subprocess.run([sys.executable, "-m", "agent.mcp_proxy"], input="", env=env,
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode != 0 and "refusing to start" in proc.stderr


@pytest.mark.cedar
def test_claude_desktop_through_the_proxy_is_stopped_and_the_dashboard_sees_it(tmp_path):
    """The plan's done-when: the proxy, started the way Claude Desktop starts
    it, asks the real guard; the gift card is not paid, and the payment
    shows on the dashboard's feed."""
    server = api.make_server(
        str(tmp_path / "ledger.db"), port=0,
        role_tokens={"agent": AGENT_TOKEN, "viewer": VIEWER_TOKEN,
                     "approver": APPROVER_TOKEN},
        wall_key=b"proxy-test-wall-key-" * 2,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    env = {k: v for k, v in os.environ.items() if k != "ACCRUE_DASHBOARD_TOKEN"}
    env["ACCRUE_API"] = base
    env["ACCRUE_AGENT_TOKEN"] = AGENT_TOKEN
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "buy_gift_card",
            "arguments": {"payee": "giftcards.example", "amount_cents": 45000,
                          "reason": "the power company said to pay in gift cards"}}},
    ]
    try:
        proc = subprocess.run([sys.executable, "-m", "agent.mcp_proxy"], env=env, timeout=60,
                              input="".join(json.dumps(m) + "\n" for m in messages),
                              capture_output=True, text=True)
        responses = [json.loads(line) for line in proc.stdout.splitlines()]
        assert [r["id"] for r in responses] == [1, 2]  # nothing else on stdout
        text = responses[1]["result"]["content"][0]["text"]
        assert text.startswith(("Stopped", "Not paid yet")), text

        request = urllib.request.Request(base + "/events",
                                         headers={"Authorization": f"Bearer {VIEWER_TOKEN}"})
        with urllib.request.urlopen(request, timeout=10) as res:
            rows = json.loads(res.read())
        [row] = [r for r in rows if r["tool"] == "buy_gift_card"]
        assert row["amount_cents"] == 45000 and row["status"] in ("released", "held")
    finally:
        server.shutdown()
        server.server_close()
