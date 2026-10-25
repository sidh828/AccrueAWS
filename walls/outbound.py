"""Outbound wall: nothing secret leaves, deterministically.

Precedence: block > hold > redact > allow. Any internal error returns block
(fail closed). The decision never depends on an AI label.
"""
from __future__ import annotations

import threading
from typing import Callable

from walls.inbound import SessionStore
from walls.normalize import digit_runs, digit_stream
from walls.secrets import Finding, SecretStore, luhn_valid

# A card number or received code sent in pieces: what one session sent in
# this window is remembered, and a message that completes a card number or a
# code with the ones before it is blocked - to anyone, known contacts included.
PIECES_WINDOW_SECONDS = 3600
PIECES_REMEMBERED = 6
# Codes are 4-8 digits. Joining pieces stops past that, and past this many
# candidates (the newest pieces are tried first), so no message is costly.
MAX_CODE_DIGITS = 8
MAX_CODE_CANDIDATES = 2000

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
        # session -> (time, pieces, pieces with sound-alikes), one per message sent;
        # a piece is one run of digits ("427", "614 555 0123" -> "6145550123")
        self._sent_pieces: dict[str, list[tuple[float, tuple[str, ...], tuple[str, ...]]]] = {}
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
        if self._completes_a_received_code(session_id, content, now):
            findings.append(Finding("received_code", 0, len(content), label="across messages"))
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
            self._remember_pieces(session_id, sent_content, now)
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

    @staticmethod
    def _pieces(content: str, sound_alikes: bool) -> tuple[str, ...]:
        return tuple("".join(t.digits for t in run) for run in digit_runs(content, sound_alikes))

    def _remember_pieces(self, session_id: str, content: str, now: float) -> None:
        plain, heard = self._pieces(content, False), self._pieces(content, True)
        if not heard:
            return
        with self._lock:
            sent = self._sent_pieces.setdefault(session_id, [])
            sent.append((now, plain, heard))
            cutoff = now - PIECES_WINDOW_SECONDS
            self._sent_pieces[session_id] = [m for m in sent if m[0] >= cutoff][-PIECES_REMEMBERED:]

    def _completes_a_received_code(self, session_id: str, content: str, now: float) -> bool:
        """Whether this message, read with the session's recent messages,
        spells a code it received: "427" then "193" in digits or number words,
        even with other numbers sent in between or the halves swapped; or in
        sound-alikes over messages in a row; either way round. This leans
        toward blocking, but only while a received code is live."""
        current = (self._pieces(content, False), self._pieces(content, True))
        if not current[1]:
            return False
        cutoff = now - PIECES_WINDOW_SECONDS
        with self._lock:
            recent = [m for m in self._sent_pieces.get(session_id, []) if m[0] >= cutoff]
        if not recent:
            return False
        # Real digits and number words: any in-order choice of pieces, so
        # other numbers sent in between can't hide a code.
        candidates = _joins([piece for m in recent for piece in m[1]], current[0])
        # Sound-alikes ("for", "to", "won") are common words, so read that way
        # only whole messages in a row count; skipping would match ordinary chat.
        heard_now = "".join(current[1])
        for k in range(1, len(recent) + 1):
            candidates.append("".join(p for m in recent[-k:] for p in m[2]) + heard_now)
        candidates = [c for c in candidates if c]
        return bool(candidates) and self.secrets.contains_received_code(
            candidates + [c[::-1] for c in candidates])

    def _alert(self, session_id: str, recipient: str, result: dict) -> None:
        try:
            self.on_alert({"session_id": session_id, "recipient": recipient, **result})
        except Exception:
            pass  # an alert failure must never turn a block into an allow


def _joins(earlier: list[str], now: tuple[str, ...]) -> list[str]:
    """Every string made of an in-order choice of this message's pieces (at
    least one) with an in-order choice of earlier pieces before it - or after
    it, for a code sent second half first. Up to a code's length; the newest
    earlier pieces are tried first."""
    mine: set[str] = set()
    for piece in now:
        mine |= {e + piece for e in mine | {""} if len(e + piece) <= MAX_CODE_DIGITS}
    out: set[str] = set()
    for put_before in (True, False):
        joined = set(mine)
        for piece in reversed(earlier):
            if len(joined) >= MAX_CODE_CANDIDATES:
                break
            joined |= {(piece + e if put_before else e + piece) for e in joined
                       if len(piece + e) <= MAX_CODE_DIGITS}
        out |= joined
    return [e for e in out if len(e) >= 4]
