"""Outbound wall: nothing secret leaves, deterministically.

Precedence: block > hold > redact > allow. Any internal error returns block
(fail closed). The decision never depends on an AI label.
"""
from __future__ import annotations

import threading
from typing import Callable

from walls.inbound import SessionStore
from walls.normalize import digit_runs
from walls.secrets import Finding, SecretStore, luhn_valid

# A card number sent in pieces: digit groups sent from one session in this
# window are remembered, and a message whose groups complete a card number
# with the ones before it is blocked - to anyone, known contacts included.
PIECES_WINDOW_SECONDS = 3600
PIECES_REMEMBERED = 6

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
        self._sent_groups: dict[str, list[tuple[float, str]]] = {}  # session -> (time, digits)
        self._lock = threading.RLock()

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
        with self._lock:
            return self._check_locked(session_id, recipient, channel, content)

    def _check_locked(self, session_id: str, recipient: str, channel: str, content: str) -> dict:
        now = self.secrets.now()
        findings = self.secrets.scan(content)
        # Only card-sized groups count; "group 2 is 1111" keeps 1111, not the 2.
        groups = self._card_groups(content)
        if self._completes_a_card(session_id, groups, now):
            findings.append(Finding("card_number", 0, len(content), label="across messages"))
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
        else:
            sent_content = result.get("redacted_content", content)
            self._remember(session_id, self._card_groups(sent_content), now)
        return result

    @staticmethod
    def _card_groups(content: str) -> list[str]:
        return [token.digits for run in digit_runs(content) for token in run
                if 4 <= len(token.digits) <= 6]

    def _recent(self, session_id: str, now: float) -> list[str]:
        cutoff = now - PIECES_WINDOW_SECONDS
        with self._lock:
            recent = [
                (sent_at, digits)
                for sent_at, digits in self._sent_groups.get(session_id, [])
                if sent_at >= cutoff
            ][-PIECES_REMEMBERED:]
            if recent:
                self._sent_groups[session_id] = recent
            else:
                self._sent_groups.pop(session_id, None)
            return [digits for _, digits in recent]

    def _remember(self, session_id: str, groups: list[str], now: float) -> None:
        if not groups:
            return
        with self._lock:
            self._sent_groups.setdefault(session_id, []).extend((now, group) for group in groups)

    def _completes_a_card(self, session_id: str, groups: list[str], now: float) -> bool:
        """Whether this message's digit groups - with words between them, or
        after the groups sent before it - end a card number. Only whole
        groups, in the order they went out - never arbitrary digits glued
        together - so ordinary numbers in separate messages rarely match."""
        # Card-shaped only: pieces of 4-6 digits (how a card is read out),
        # 15 or 16 digits in all, starting like a card (Amex 3, Visa 4,
        # Mastercard 2/5, Discover 6). Random numbers that happen to pass
        # Luhn when glued (about one in ten) are otherwise flagged.
        if not groups:
            return False
        sequence = self._recent(session_id, now) + groups
        for end in range(len(sequence) - len(groups), len(sequence)):
            digits = ""
            for start in range(end, -1, -1):
                digits = sequence[start] + digits
                if len(digits) > 16:
                    break
                if len(digits) in (15, 16) and digits[0] in "23456" and luhn_valid(digits):
                    return True
        return False

    def _alert(self, session_id: str, recipient: str, result: dict) -> None:
        try:
            self.on_alert({"session_id": session_id, "recipient": recipient, **result})
        except Exception:
            pass  # an alert failure must never turn a block into an allow
