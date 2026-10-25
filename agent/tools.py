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
import os
import threading
import time
import urllib.request
import uuid
from typing import Callable, Protocol

from guard import authorize as family_policy
from guard.tool_contract import DEFAULT_TOOL_CATEGORIES, category_matches_tool
from walls.inbound import InboundWall, SessionStore, is_trusted, wrap_untrusted
from walls.outbound import OutboundWall
from walls.secrets import SecretStore

TOOL_CATEGORY = DEFAULT_TOOL_CATEGORIES

# Keep the deterministic stand-in on the same configured windows, limits, and
# rule outcomes as the real Cedar-backed guard.
WINDOW_S = int(family_policy.BUDGET_WINDOW.total_seconds())
RECENT_PAYEE_WINDOW_S = int(family_policy.RECENT_PAYEE_WINDOW.total_seconds())
HOUSEHOLD_TAINT_S = int(family_policy.HOUSEHOLD_TAINT.total_seconds())
BREAKER_WINDOW_S = int(family_policy.BREAKER_WINDOW.total_seconds())
KNOWN_BILL_LOOKBACK_S = int(family_policy.KNOWN_BILL_LOOKBACK.total_seconds())
KNOWN_BILL_CYCLE_S = int(family_policy.KNOWN_BILL_CYCLE.total_seconds())
LIMITS_NORMAL = {
    "day": family_policy.FAMILY_LIMITS["day"],
    "gift_card_day": family_policy.FAMILY_LIMITS["gift_card_day"],
    "new_payee_first": family_policy.FAMILY_LIMITS["new_payee_first"],
    "recent_payees": family_policy.FAMILY_LIMITS["recent_payees"],
}
LIMITS_TAINTED = {
    "day": family_policy.FAMILY_LIMITS["day_flagged"],
    "gift_card_day": 0,
    "new_payee_first": 0,
    "recent_payees": family_policy.FAMILY_LIMITS["recent_payees_flagged"],
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
    """Deterministic in-memory simulation of the real guard's family-rule outcomes.

    The Cedar policy and its configured limits/outcome mapping remain the source
    of truth. Keep the attack suite's fake results labeled as simulations.
    """

    def __init__(self, clock: Callable[[], float] = time.time, known_payees: set[str] | None = None,
                 bound_person: str = "mom", known_bills: dict[str, int] | None = None):
        self.clock = clock
        self.secrets = SecretStore(clock)
        self.sessions = SessionStore(clock)
        self.inbound_wall = InboundWall(self.sessions, self.secrets)
        self.outbound_wall = OutboundWall(self.secrets, self.sessions)
        self.known_payees = set(known_payees or {"power-company.example", "landlord.example"})
        self.known_payees.update(known_bills or {})
        self._established_payees = set(self.known_payees)
        self._known_bill_history = {
            payee: [(amount, self.clock() - 30 * 24 * 3600)]
            for payee, amount in (known_bills or {}).items()
        }
        self.bound_person = bound_person.lower()
        self.fault: str | None = None        # set to any string to simulate "Cedar is down"
        self.events: list[dict] = []
        self._household_taint_at: float | None = None
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
        if req["tool"] not in TOOL_CATEGORY or not category_matches_tool(req["tool"], req["category"]):
            return {**_hold("invalid_tool_category"), "decision": "deny", "needs_approval": False}
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
            now, cat = self.clock(), req["category"]
            tainted = tainted or (
                self._household_taint_at is not None
                and now - self._household_taint_at <= HOUSEHOLD_TAINT_S
            )
            lim = LIMITS_TAINTED if tainted else LIMITS_NORMAL
            mine = [e for e in self.events if e["person"] == self.bound_person]
            live = [e for e in mine if e["decision"] == "allow" and now - e["_t"] < WINDOW_S]
            day = sum(e["amount_cents"] for e in live if not e.get("_known_bill"))
            gift = sum(e["amount_cents"] for e in live if e["category"] == "gift_card") + (amt if cat == "gift_card" else 0)
            denials = [e for e in mine if e["decision"] == "deny" and now - e["_t"] < BREAKER_WINDOW_S]
            # As in the real guard (authorize.KNOWN_BILL_CYCLE): a known bill is
            # paid once a cycle, so it's the last payment to this payee that
            # decides, and only if it was 20 to 45 days ago.
            paid = [(e["amount_cents"], e["_t"]) for e in mine
                    if e["decision"] == "allow" and e["payee"] == req["payee"]]
            last = paid[-1] if paid else (self._known_bill_history.get(req["payee"]) or [None])[-1]
            last_bill = None
            if last is not None and KNOWN_BILL_CYCLE_S <= now - last[1] < KNOWN_BILL_LOOKBACK_S:
                last_bill = last[0]
            known_bill = cat in family_policy.KNOWN_BILL_CATEGORIES and last_bill is not None
            new_payee = req["payee"] not in self.known_payees
            first_paid_by_payee = {}
            for event in mine:
                if event["decision"] == "allow" and event["payee"] is not None:
                    first_paid_by_payee[event["payee"]] = min(
                        first_paid_by_payee.get(event["payee"], event["_t"]),
                        event["_t"],
                    )
            payee_payments = [
                e for e in mine
                if e["decision"] == "allow" and e["payee"] == req["payee"]
            ]
            first_paid = first_paid_by_payee.get(req["payee"])
            recent_payee = (
                req["payee"] not in self._established_payees
                and first_paid is not None
                and now - first_paid <= RECENT_PAYEE_WINDOW_S
            )
            payee_recent_total = sum(
                e["amount_cents"] for e in payee_payments
                if now - e["_t"] <= RECENT_PAYEE_WINDOW_S
            ) + amt
            recent_payees_total = sum(
                e["amount_cents"] for e in mine
                if e["decision"] == "allow"
                and e["payee"] is not None
                and e["payee"] not in self._established_payees
                and first_paid_by_payee.get(e["payee"]) is not None
                and now - first_paid_by_payee[e["payee"]] <= RECENT_PAYEE_WINDOW_S
                and now - e["_t"] <= RECENT_PAYEE_WINDOW_S
            )
            if new_payee or recent_payee:
                recent_payees_total += amt

            fired: set[str] = set()
            # Over the day's limit: stopped for someone new (a bail wire), waits
            # for the family for someone she's paid before (family.cedar).
            if not known_bill and day + amt > lim["day"]:
                fired.add("daily_cap" if new_payee else "daily_cap_needs_approval")
            if (new_payee or recent_payee) and recent_payees_total > lim["recent_payees"]:
                fired.add("recent_payee_cap")
            if cat == "gift_card":
                if tainted:
                    fired.add("gift_card_needs_approval")
                elif gift > lim["gift_card_day"]:
                    fired.add("gift_card_daily_cap")
            if new_payee:
                if tainted:
                    fired.add("new_payee_needs_approval")
                elif amt > lim["new_payee_first"]:
                    fired.add("new_payee_cap")
            elif recent_payee and not tainted and payee_recent_total > lim["new_payee_first"]:
                fired.add("new_payee_month_cap")
            if known_bill and amt * 5 > last_bill * 6:
                fired.add("bill_increase")
            breaker_limit = family_policy.FAMILY_LIMITS[
                "breaker_denials_flagged" if tainted else "breaker_denials"
            ]
            if len(denials) >= breaker_limit:
                fired.add("breaker")

            ordered = [rule for rule in family_policy.RULE_OUTCOMES if rule in fired]
            denies = [rule for rule in ordered if family_policy.RULE_OUTCOMES[rule] == "deny"]
            rule = (denies or ordered or ["ok"])[0]
            decision = family_policy.RULE_OUTCOMES[rule] if rule != "ok" else "allow"

            event_id = len(self.events) + 1
            event = self._event(event_id, req, _STATUS[decision], decision, rule, now)
            event["_known_bill"] = known_bill
            self.events.append(event)
            resp = {
                "decision": decision, "rule": rule,
                "totals": {"day": day + (0 if known_bill else amt),
                           "gift_card_day": gift, "recent_payees": recent_payees_total},
                "limits": {
                    "day": lim["day"],
                    "gift_card_day": lim["gift_card_day"],
                    "new_payee_first": lim["new_payee_first"],
                    "recent_payees": lim["recent_payees"],
                },
                "needs_approval": decision == "hold", "event_id": event_id,
            }
            self._by_request[rid] = (fingerprint, resp)
            if decision == "allow":
                self.known_payees.add(req["payee"])
                if cat in family_policy.KNOWN_BILL_CATEGORIES:
                    self._known_bill_history.setdefault(req["payee"], []).append((amt, now))
            return resp

    def inbound(self, session_id, source, content):
        result = self.inbound_wall.ingest(session_id, source, content)
        if not result.trusted:
            with self._lock:
                self._household_taint_at = self.clock()
        return result.to_contract()

    def outbound(self, session_id, recipient, channel, content):
        return self.outbound_wall.check(session_id, recipient, channel, content)


# --------------------------------------------------------------------------
class HttpGuard:
    """Real guard over HTTP. Any network or parse error becomes hold/block (fail closed)."""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", timeout: float = 5.0,
                 token: str | None = None):
        self.base, self.timeout = base_url.rstrip("/"), timeout
        self.token = token if token is not None else os.environ.get("ACCRUE_AGENT_TOKEN")

    def _post(self, path: str, body: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode(), headers=headers
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

    def _pay(
        self,
        tool: str,
        payee: str,
        amount_cents: int,
        reason: str,
        request_id: str | None = None,
        category: str | None = None,
    ) -> dict:
        selected_category = category or TOOL_CATEGORY[tool]
        req = {
            "person": self.person, "token": self.token, "chain": self.chain, "tool": tool,
            "amount_cents": amount_cents, "payee": payee, "category": selected_category,
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

    def pay_bill(
        self, payee: str, amount_cents: int, reason: str = "", *,
        category: str = "bill", **kw
    ) -> dict:
        return self._pay("pay_bill", payee, amount_cents, reason, category=category, **kw)

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
