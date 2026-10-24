"""The two weaker defenses the attack table compares us against.

They are deliberately honest, not strawmen:
  PerCallGuard - the status quo. Approves any single payment up to $500. Remembers nothing.
  ScamWallOnly - a label-based classifier in front of the agent. It flags a session when an
                 inbound message trips a scam/injection label, then refuses everything in that
                 session. No running totals, no source-based taint.
"""
from __future__ import annotations

import threading

from walls.inbound import deterministic_labels, is_trusted

PER_CALL_LIMIT = 50_000


def _per_call(req: dict) -> dict:
    amt = req["amount_cents"]
    ok = type(amt) is int and 0 < amt <= PER_CALL_LIMIT
    return {"decision": "allow" if ok else "deny", "rule": "per_call_ok" if ok else "per_call_cap",
            "totals": {}, "limits": {"per_call": PER_CALL_LIMIT}, "needs_approval": False, "event_id": None}


class PerCallGuard:
    def __init__(self, clock=None):
        pass

    def authorize(self, req):
        return _per_call(req)

    def inbound(self, session_id, source, content):
        return {"trusted": is_trusted(source), "tainted": False, "labels": []}

    def outbound(self, session_id, recipient, channel, content):
        return {"decision": "allow", "findings": []}


class ScamWallOnly:
    def __init__(self, clock=None):
        self.flagged: set[str] = set()
        self._lock = threading.Lock()

    def authorize(self, req):
        with self._lock:
            flagged = req["session_id"] in self.flagged
        if flagged:
            return {"decision": "deny", "rule": "scam_wall", "totals": {}, "limits": {},
                    "needs_approval": False, "event_id": None}
        return _per_call(req)

    def inbound(self, session_id, source, content):
        labels = deterministic_labels(content)
        if labels:
            with self._lock:
                self.flagged.add(session_id)
        return {"trusted": is_trusted(source), "tainted": False, "labels": labels}

    def outbound(self, session_id, recipient, channel, content):
        with self._lock:
            flagged = session_id in self.flagged
        return {"decision": "block" if flagged else "allow", "findings": []}
