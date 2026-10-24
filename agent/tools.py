"""Agent tools. Every tool calls the guard and nothing else.

The agent holds a token and no money. There is deliberately NO override,
approve, or clear-taint tool here; tests/test_walls.py asserts that.

Rule for every tool: an error, timeout, or malformed answer from the guard means
NOT PAID / NOT SENT. Only an explicit "allow" (or allow/redact for messages) moves anything.

Two guard clients share one interface:
  FakeGuard  - in-memory stand-in so scenarios run before Dharvik's engine is wired in
  HttpGuard  - talks to the real FastAPI guard using the frozen contract
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
import uuid
from typing import Callable, Protocol

from walls.inbound import InboundWall, SessionStore, is_trusted, wrap_untrusted
from walls.outbound import OutboundWall
from walls.secrets import SecretStore

TOOL_CATEGORY = {"pay_bill": "bill", "buy_gift_card": "gift_card", "send_zelle": "transfer"}

# Spending rules (section 10). Integer cents everywhere.
LIMITS_NORMAL = {"day": 50_000, "gift_card_day": 10_000, "new_payee_first": 20_000}
LIMITS_TAINTED = {"day": 10_000, "gift_card_day": 0, "new_payee_first": 0}
WINDOW_S = 24 * 3600     # "today" = rolling 24 hours
BREAKER_WINDOW_S = 600

# PLACEHOLDER until the team maps every rule to an outcome: (normal column, tainted column).
RULE_OUTCOME = {
    "daily_cap": ("deny", "deny"),
    "gift_card_daily_cap": ("deny", "hold"),   # tainted: "$0, needs approval"
    "new_payee_approval": ("hold", "hold"),
    "breaker": ("hold", "hold"),
}
_STATUS = {"allow": "allowed", "deny": "released", "hold": "held"}


class Guard(Protocol):
    def authorize(self, req: dict) -> dict: ...
    def inbound(self, session_id: str, source: str, content: str) -> dict: ...
    def outbound(self, session_id: str, recipient: str, channel: str, content: str) -> dict: ...


def _hold(rule: str = "guard_unavailable") -> dict:
    return {"decision": "hold", "rule": rule, "totals": {}, "limits": {}, "needs_approval": True, "event_id": None}


# --------------------------------------------------------------------------
class FakeGuard:
    """In-memory guard mirroring the contract as revised in review:
    totals include the current request; needs_approval is true exactly when decision == hold;
    held and denied amounts don't count toward totals; rolling 24h window; the person comes
    from the server side (bound_person), never from the request; retries by request_id return
    the original decision. This is a stand-in, not the engine: don't quote its numbers."""

    def __init__(self, clock: Callable[[], float] = time.time, known_payees: set[str] | None = None,
                 bound_person: str = "mom"):
        self.clock = clock
        self.secrets = SecretStore(clock)
        self.sessions = SessionStore(clock)
        self.inbound_wall = InboundWall(self.sessions, self.secrets)
        self.outbound_wall = OutboundWall(self.secrets, self.sessions)
        self.known_payees = set(known_payees or {"power-company.example", "landlord.example"})
        self.bound_person = bound_person.lower()
        self.fault: str | None = None        # set to any string to simulate "Cedar is down"
        self.events: list[dict] = []
        self._by_request: dict[str, tuple[tuple, dict]] = {}
        self._lock = threading.Lock()         # stands in for BEGIN IMMEDIATE

    def limits(self, tainted: bool = False) -> dict:
        return dict(LIMITS_TAINTED if tainted else LIMITS_NORMAL)

    def authorize(self, req: dict) -> dict:
        try:
            if self.fault:
                raise RuntimeError(self.fault)
            return self._authorize(req)
        except Exception:  # fail closed, and leave a record
            return self._record_unavailable(req)

    def _record_unavailable(self, req: dict) -> dict:
        resp = _hold("guard_unavailable")
        try:
            with self._lock:
                resp["event_id"] = len(self.events) + 1
                self.events.append(self._event(resp["event_id"], req, "held", "hold", "guard_unavailable", self.clock()))
        except Exception:
            pass
        return resp

    def _event(self, event_id: int, req: dict, status: str, decision: str, rule: str, now: float) -> dict:
        chain = [c.lower() for c in (req.get("chain") or [])]
        return {
            "event_id": event_id, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "status": status, "person": self.bound_person, "chain": chain,
            "scope_id": "/".join([self.bound_person] + chain[1:]),
            "tool": req.get("tool"), "amount_cents": req.get("amount_cents") if type(req.get("amount_cents")) is int else 0,
            "payee": req.get("payee"), "category": req.get("category"),
            "decision": decision, "rule": rule, "session_id": req.get("session_id"), "_t": now,
        }

    def _authorize(self, req: dict) -> dict:
        amt = req["amount_cents"]
        if type(amt) is not int or amt <= 0:  # no floats, no bools, nothing zero or negative
            return {**_hold("invalid_amount"), "decision": "deny", "needs_approval": False}
        fingerprint = (req["tool"], amt, req["payee"], req["category"], tuple(req["chain"]))
        with self._lock:
            rid = req["request_id"]
            if rid in self._by_request:
                fp, original = self._by_request[rid]
                if fp == fingerprint:
                    return original  # a retry gets the original answer, never counted twice
                return {**_hold("request_id_reuse"), "decision": "deny", "needs_approval": False}
            tainted = self.sessions.is_tainted(req["session_id"])
            lim = LIMITS_TAINTED if tainted else LIMITS_NORMAL
            now, cat = self.clock(), req["category"]
            mine = [e for e in self.events if e["person"] == self.bound_person]
            live = [e for e in mine if e["status"] in ("pending", "allowed") and now - e["_t"] < WINDOW_S]
            day = sum(e["amount_cents"] for e in live) + amt
            gift = sum(e["amount_cents"] for e in live if e["category"] == "gift_card") + (amt if cat == "gift_card" else 0)
            denials = [e for e in mine if e["decision"] == "deny" and now - e["_t"] < BREAKER_WINDOW_S]

            rule = "ok"
            if len(denials) >= (1 if tainted else 3):
                rule = "breaker"
            elif day > lim["day"]:
                rule = "daily_cap"
            elif cat == "gift_card" and gift > lim["gift_card_day"]:
                rule = "gift_card_daily_cap"
            elif req["payee"] not in self.known_payees and amt > lim["new_payee_first"]:
                rule = "new_payee_approval"
            decision = "allow" if rule == "ok" else RULE_OUTCOME[rule][1 if tainted else 0]

            event_id = len(self.events) + 1
            self.events.append(self._event(event_id, req, _STATUS[decision], decision, rule, now))
            if decision == "allow":
                self.known_payees.add(req["payee"])
            resp = {
                "decision": decision, "rule": rule,
                "totals": {"day": day, "gift_card_day": gift},
                "limits": {"day": lim["day"], "gift_card_day": lim["gift_card_day"]},
                "needs_approval": decision == "hold", "event_id": event_id,
            }
            self._by_request[rid] = (fingerprint, resp)
            return resp

    def inbound(self, session_id, source, content):
        return self.inbound_wall.ingest(session_id, source, content).to_contract()

    def outbound(self, session_id, recipient, channel, content):
        return self.outbound_wall.check(session_id, recipient, channel, content)


# --------------------------------------------------------------------------
class HttpGuard:
    """Real guard over HTTP. Any network or parse error becomes hold/block (fail closed)."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 5.0):
        self.base, self.timeout = base_url.rstrip("/"), timeout

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())

    def authorize(self, req):
        try:
            return self._post("/authorize", req)
        except Exception:
            return _hold("guard_unavailable")

    def inbound(self, session_id, source, content):
        try:
            return self._post("/inbound", {"session_id": session_id, "source": source, "content": content})
        except Exception:
            return {"trusted": False, "tainted": True, "labels": ["guard_unavailable"]}

    def outbound(self, session_id, recipient, channel, content):
        try:
            return self._post("/outbound", {"session_id": session_id, "recipient": recipient,
                                            "channel": channel, "content": content})
        except Exception:
            return {"decision": "block", "findings": [{"kind": "guard_unavailable"}]}


# --------------------------------------------------------------------------
class ToolBox:
    """What the agent can do. Each method asks the guard; none moves money itself.

    origin="mcp" marks a session driven by Claude Desktop through the MCP proxy. There the
    client reads mail and SMS itself, so inbound text never reaches /inbound; the session
    therefore starts tainted (stricter rules) and the daughter clears it.
    """

    def __init__(self, guard: Guard, person: str = "mom", chain: list[str] | None = None,
                 token: str | None = None, session_id: str | None = None, origin: str = "agent"):
        self.guard = guard
        self.person = person
        self.chain = chain or [person, "bills-agent"]
        self.token = token
        self.session_id = session_id or f"sess-{uuid.uuid4().hex[:8]}"
        self.origin = origin
        if origin == "mcp":
            # An untrusted source taints through the existing /inbound contract; no new endpoint.
            self._safe_inbound("mcp_session_start", "")

    def _safe_inbound(self, source: str, content: str) -> dict:
        try:
            meta = self.guard.inbound(self.session_id, source, content)
            if not isinstance(meta, dict):
                raise ValueError("bad inbound response")
            return meta
        except Exception:
            return {"trusted": False, "tainted": True, "labels": ["guard_unavailable"]}

    def _pay(self, tool: str, payee: str, amount_cents: int, reason: str, request_id: str | None = None) -> dict:
        req = {
            "person": self.person, "token": self.token, "chain": self.chain, "tool": tool,
            "amount_cents": amount_cents, "payee": payee, "category": TOOL_CATEGORY[tool],
            "reason": reason, "request_id": request_id or str(uuid.uuid4()), "session_id": self.session_id,
        }
        try:
            resp = self.guard.authorize(req)
        except Exception:
            resp = _hold("guard_unavailable")
        if not isinstance(resp, dict) or resp.get("decision") not in ("allow", "deny", "hold"):
            resp = _hold("guard_bad_response")
        # Paid only on an explicit allow. Anything else, including errors, is not paid.
        return {"ok": resp["decision"] == "allow" and not resp.get("error"), **resp}

    def pay_bill(self, payee: str, amount_cents: int, reason: str = "", **kw) -> dict:
        return self._pay("pay_bill", payee, amount_cents, reason, **kw)

    def buy_gift_card(self, payee: str, amount_cents: int, reason: str = "", **kw) -> dict:
        return self._pay("buy_gift_card", payee, amount_cents, reason, **kw)

    def send_zelle(self, payee: str, amount_cents: int, reason: str = "", **kw) -> dict:
        return self._pay("send_zelle", payee, amount_cents, reason, **kw)

    def receive_message(self, source: str, content: str) -> dict:
        """Everything entering the agent's context passes here first. The runtime supplies
        `source`, never the model. Returns text that is safe to show the model."""
        meta = self._safe_inbound(source, content)
        trusted = bool(meta.get("trusted")) and is_trusted(source)
        return {**meta, "text_for_model": content if trusted else wrap_untrusted(content, source)}

    def send_message(self, recipient: str, channel: str, content: str) -> dict:
        try:
            verdict = self.guard.outbound(self.session_id, recipient, channel, content)
            if not isinstance(verdict, dict) or verdict.get("decision") not in ("allow", "redact", "hold", "block"):
                raise ValueError("bad outbound response")
        except Exception:
            verdict = {"decision": "block", "findings": [{"kind": "guard_unavailable"}]}
        redacted = verdict.get("redacted_content")
        sent = verdict["decision"] == "allow" or (verdict["decision"] == "redact" and redacted is not None)
        body = (content if verdict["decision"] == "allow" else redacted) if sent else None
        return {"sent": sent, "delivered_content": body, **verdict}

    def call(self, name: str, **args) -> dict:
        if name not in TOOL_NAMES:
            return {"ok": False, "error": f"unknown tool {name}"}
        return getattr(self, name)(**args)


TOOL_NAMES = {"pay_bill", "buy_gift_card", "send_zelle", "send_message", "receive_message"}
