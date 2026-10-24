"""Outbound wall: nothing secret leaves, deterministically.

Precedence: block > hold > redact > allow. Any internal error returns block
(fail closed). The decision never depends on an AI label.
"""
from __future__ import annotations

import threading
from typing import Callable

from walls.inbound import SessionStore
from walls.normalize import tokens
from walls.secrets import Finding, SecretStore, luhn_valid

BLOCK_KINDS = {"received_code", "card_number", "ssn", "vault_secret"}
REDACT_KINDS = {"routing_number", "account_number"}
CARD_PIECE_WINDOW_SECONDS = 3600


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
        self._card_pieces: dict[str, list[tuple[float, str]]] = {}
        self._card_pieces_lock = threading.RLock()

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
        with self._card_pieces_lock:
            now = self.secrets.now()
            findings = self.secrets.scan(content)
            pieces = self._card_groups(content)
            assembled_card = self._completes_card(session_id, pieces, now)
            if assembled_card and not any(f.kind == "card_number" for f in findings):
                findings.append(Finding("card_number", 0, len(content), label="assembled"))

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
            if decision in ("allow", "redact"):
                sent_content = result.get("redacted_content", content)
                self._remember_card_groups(session_id, self._card_groups(sent_content), now)
            if decision in ("block", "hold"):
                self._alert(session_id, recipient, result)
            return result

    @staticmethod
    def _card_groups(content: str) -> list[str]:
        return [part.digits for part in tokens(content) if part.digits and 4 <= len(part.digits) <= 6]

    def _completes_card(self, session_id: str, pieces: list[str], now: float) -> bool:
        cutoff = now - CARD_PIECE_WINDOW_SECONDS
        for stored_session, stored_pieces in list(self._card_pieces.items()):
            active = [(sent_at, digits) for sent_at, digits in stored_pieces if sent_at >= cutoff]
            if active:
                self._card_pieces[stored_session] = active
            else:
                del self._card_pieces[stored_session]
        history = self._card_pieces.get(session_id)
        if history is None:
            return False
        candidate = [digits for _, digits in history]
        for piece in pieces:
            candidate.append(piece)
            for start in range(len(candidate) - 1, -1, -1):
                groups = candidate[start:]
                digits = "".join(groups)
                if len(digits) > 16:
                    break
                if (
                    len(digits) in (15, 16)
                    and digits[0] in "23456"
                    and luhn_valid(digits)
                ):
                    return True
        return False

    def _remember_card_groups(self, session_id: str, pieces: list[str], now: float) -> None:
        if not pieces:
            return
        history = self._card_pieces.setdefault(session_id, [])
        history.extend((now, digits) for digits in pieces)

    def _alert(self, session_id: str, recipient: str, result: dict) -> None:
        try:
            self.on_alert({"session_id": session_id, "recipient": recipient, **result})
        except Exception:
            pass  # an alert failure must never turn a block into an allow
