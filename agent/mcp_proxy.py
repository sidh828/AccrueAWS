"""The guard as an MCP server, so Claude Desktop pays bills through it.

Claude Desktop starts this over stdio and sees three tools: pay_bill,
buy_gift_card and send_zelle. Each one asks the guard (POST /authorize) and
answers with a sentence ("Stopped: ..."). Nothing here can move money or
approve anything: there's no override tool, and the dashboard's token must
never be in this process's environment (it refuses to start if it is).

Claude Desktop reads mail and SMS itself, so that text never reaches
/inbound. Sessions from here start tainted (ToolBox origin="mcp"), and the
stricter rules apply until the daughter clears them.

claude_desktop_config.json:

    {"mcpServers": {"accrue": {
        "command": "/path/to/AccrueAWS/.venv/bin/python",
        "args": ["-m", "agent.mcp_proxy"],
        "cwd": "/path/to/AccrueAWS",
        "env": {"ACCRUE_API": "http://127.0.0.1:8000",
                "ACCRUE_AGENT_TOKEN": "<the guard's ACCRUE_AGENT_TOKEN>",
                "ACCRUE_DELEGATION_TOKEN": "<python -m guard.tokens mint ...>"}}}}

Without ACCRUE_AGENT_TOKEN the guard answers 401, so every payment comes back
"the guard couldn't check it" (held, fail closed).

ACCRUE_DELEGATION_TOKEN is the signed delegation from guard.tokens, sent in
the request body as "token". It's a different thing from the agent's login
(ACCRUE_AGENT_TOKEN in #37's role logins, which HttpGuard sends as a header),
so the two get separate names.

The MCP protocol is newline-delimited JSON-RPC 2.0 on stdin/stdout, written
out by hand here (initialize, tools/list, tools/call, ping) so the demo
laptop needs no extra package. Logs go to stderr: stdout is the protocol.
"""

import json
import os
import sys

from agent.tools import HttpGuard, ToolBox

SERVER = {"name": "accrue-guard", "version": "0.1.0"}
PROTOCOL = "2025-06-18"

_AMOUNT = {"type": "integer", "minimum": 1,
           "description": "Amount in cents, a whole number: 45000 means $450.00."}
_PAYEE = {"type": "string", "description": "Who gets paid, e.g. ohio-power.example."}
_REASON = {"type": "string", "description": "Why, in a few words."}

TOOLS = [
    {"name": "pay_bill",
     "description": "Ask the family's guard to pay a bill. The guard decides; you can't override it.",
     "inputSchema": {"type": "object", "required": ["payee", "amount_cents"], "properties": {
         "payee": _PAYEE, "amount_cents": _AMOUNT, "reason": _REASON,
         "category": {"type": "string", "enum": ["utility", "rent", "bill"],
                      "description": "utility or rent for a known monthly bill; bill otherwise."}}}},
    {"name": "buy_gift_card",
     "description": "Ask the family's guard to buy a gift card. The guard decides; you can't override it.",
     "inputSchema": {"type": "object", "required": ["payee", "amount_cents"], "properties": {
         "payee": _PAYEE, "amount_cents": _AMOUNT, "reason": _REASON}}},
    {"name": "send_zelle",
     "description": "Ask the family's guard to send money by Zelle. The guard decides; you can't override it.",
     "inputSchema": {"type": "object", "required": ["payee", "amount_cents"], "properties": {
         "payee": _PAYEE, "amount_cents": _AMOUNT, "reason": _REASON}}},
]

# What the agent is told, in plain words. Keep close to dashboard/alerts.py.
RULES = {
    "daily_cap": "over the 24-hour limit",
    "daily_cap_needs_approval": "over the 24-hour limit; the family has to OK it",
    "gift_card_daily_cap": "over the gift card limit",
    "gift_card_needs_approval": "gift cards need the family's OK right now",
    "new_payee_cap": "too much for a first payment to someone new",
    "new_payee_needs_approval": "a payment to someone new needs the family's OK",
    "new_payee_month_cap": "too much to new payees this month",
    "recent_payee_cap": "too many new payees recently",
    "bill_increase": "more than 20% above last month's bill",
    "breaker": "payments are paused after repeated blocked attempts",
    "delegation_tool": "this assistant isn't allowed to use that payment method",
    "delegation_budget": "over this assistant's budget",
    "guard_unavailable": "the guard couldn't check it, so nothing was paid",
}


def money(cents):
    dollars, rest = divmod(cents, 100)
    return f"${dollars:,}.{rest:02d}"


def sentence(result, amount_cents, payee):
    """The guard's answer as one sentence for the model."""
    what = f"{money(amount_cents)} to {payee}"
    if result.get("ok"):
        return f"Paid: {what}."
    rule = result.get("rule")
    why = RULES.get(rule) if isinstance(rule, str) else None
    why = why or "a spending rule"
    if result.get("decision") == "hold":
        return (f"Not paid yet: {what} is waiting for the family's OK ({why}). "
                "Don't retry or work around it.")
    return f"Stopped: {what} was not paid ({why}). Don't retry or work around it."


class Proxy:
    def __init__(self, tools):
        self.tools = tools  # an agent.tools.ToolBox

    def handle(self, message):
        """One JSON-RPC message in; the response dict, or None for a notification."""
        if not isinstance(message, dict):
            return _error(None, -32600, "invalid request")
        method, msg_id = message.get("method"), message.get("id")
        if msg_id is None:
            return None  # a notification (e.g. notifications/initialized): nothing to say
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion")
            return _result(msg_id, {
                "protocolVersion": requested if isinstance(requested, str) else PROTOCOL,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER,
                "instructions": "Payments go through the family's guard. A stopped or waiting "
                                "payment is final for you: tell the person, don't retry.",
            })
        if method == "ping":
            return _result(msg_id, {})
        if method == "tools/list":
            return _result(msg_id, {"tools": TOOLS})
        if method == "tools/call":
            return _result(msg_id, self.call(message.get("params") or {}))
        return _error(msg_id, -32601, f"no method {method!r}")

    def call(self, params):
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in {tool["name"] for tool in TOOLS}:
            return _text(f"There's no tool called {name!r}.", error=True)
        payee, cents = args.get("payee"), args.get("amount_cents")
        if not isinstance(payee, str) or not payee.strip():
            return _text("Not paid: say who to pay (payee).", error=True)
        if type(cents) is not int or cents <= 0:
            return _text("Not paid: amount_cents has to be a whole number of cents above 0.",
                         error=True)
        reason = args.get("reason") if isinstance(args.get("reason"), str) else ""
        try:
            if name == "pay_bill":
                category = args.get("category") if args.get("category") in ("utility", "rent") else "bill"
                result = self.tools.pay_bill(payee, cents, reason, category=category)
            elif name == "buy_gift_card":
                result = self.tools.buy_gift_card(payee, cents, reason)
            else:
                result = self.tools.send_zelle(payee, cents, reason)
        except Exception as err:  # fail closed: whatever went wrong, nothing was paid
            print(f"accrue proxy: {name} failed: {err!r}", file=sys.stderr, flush=True)
            result = {"ok": False, "decision": "hold", "rule": "guard_unavailable"}
        print(f"accrue proxy: {name} {money(cents)} to {payee}: "
              f"{result.get('decision')} {result.get('rule')}", file=sys.stderr, flush=True)
        return _text(sentence(result, cents, payee))


def _result(msg_id, result):
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _text(text, error=False):
    return {"content": [{"type": "text", "text": text}], "isError": error}


def serve(proxy, stdin=sys.stdin, stdout=sys.stdout):
    for line in stdin:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            response = _error(None, -32700, "parse error")
        else:
            response = proxy.handle(message)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


def main():
    if os.environ.get("ACCRUE_DASHBOARD_TOKEN"):
        # The agent side must never hold the credential that approves payments.
        sys.exit("accrue proxy: refusing to start with ACCRUE_DASHBOARD_TOKEN in the "
                 "environment; remove it from the Claude Desktop config")
    api = os.environ.get("ACCRUE_API", "http://127.0.0.1:8000")
    tools = ToolBox(HttpGuard(api), token=os.environ.get("ACCRUE_DELEGATION_TOKEN") or None,
                    origin="mcp")
    print(f"accrue proxy: asking the guard at {api}", file=sys.stderr, flush=True)
    serve(Proxy(tools))


if __name__ == "__main__":
    main()
