"""Outbound wall: nothing secret leaves, deterministically.

Precedence: block > hold > redact > allow. Any internal error returns block
(fail closed). The decision never depends on an AI label.
"""
from __future__ import annotations

from typing import Callable

from walls.inbound import SessionStore
from walls.secrets import Finding, SecretStore

BLOCK_KINDS = {"received_code", "card_number", "ssn", "vault_secret"}
REDACT_KINDS = {"routing_number", "account_number"}


def _norm(recipient: str) -> str:
    return (recipient or "").strip().lower()


def redact(content: str, findings: list[Finding]) -> str:
    out = content
    for f in sorted((f for f in findings if f.kind in REDACT_KINDS), key=lambda f: f.start, reverse=True):
        out = out[: f.start] + "[removed]" + out[f.end :]
    return out


class OutboundWall:
    def __init__(
        self,
        secrets: SecretStore,
        sessions: SessionStore,
        contacts: set[str] | None = None,
        on_alert: Callable[[dict], None] | None = None,
    ):
        self.secrets = secrets
        self.sessions = sessions
        self.contacts = {_norm(c) for c in (contacts or set())}
        self.on_alert = on_alert or (lambda event: None)

    def add_contact(self, recipient: str) -> None:
        self.contacts.add(_norm(recipient))

    def check(self, session_id: str, recipient: str, channel: str, content: str) -> dict:
        """Exact shape of POST /outbound's response (plus redacted_content when redacting)."""
        try:
            return self._check(session_id, recipient, channel, content)
        except Exception as exc:  # fail closed
            result = {"decision": "block", "findings": [{"kind": "wall_error", "label": type(exc).__name__}]}
            self._alert(session_id, recipient, result)
            return result

    def _check(self, session_id: str, recipient: str, channel: str, content: str) -> dict:
        findings = self.secrets.scan(content)
        kinds = {f.kind for f in findings}
        decision = "allow"
        if kinds & REDACT_KINDS:
            decision = "redact"
        if _norm(recipient) not in self.contacts and self.sessions.is_tainted(session_id):
            decision = "hold"
            findings.append(Finding("unknown_recipient", 0, 0))
        if kinds & BLOCK_KINDS:
            decision = "block"
        result: dict = {"decision": decision, "findings": [f.to_dict() for f in findings]}
        if decision == "redact":
            result["redacted_content"] = redact(content, findings)
        if decision in ("block", "hold"):
            self._alert(session_id, recipient, result)
        return result

    def _alert(self, session_id: str, recipient: str, result: dict) -> None:
        try:
            self.on_alert({"session_id": session_id, "recipient": recipient, **result})
        except Exception:
            pass  # an alert failure must never turn a block into an allow
