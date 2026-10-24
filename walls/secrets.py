"""Deterministic secret detection. No AI, no guessing: exact matches and checksums.

Used by the outbound wall (block secrets leaving) and the inbound wall
(remember verification codes that arrive). Findings never contain the secret
value itself, only its kind and position, so logs and dashboards can't leak it.
"""
from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Callable

from walls.normalize import digit_runs, digit_stream, nfkc
from walls.storage import WallStateStore

CODE_WINDOW_SECONDS = 3600  # remember received codes for one hour

# "your code is 427193", "verification code: 4271", "427193 is your code"
_CODE_AFTER = re.compile(
    r"(?i)(?:code|otp|passcode|pin|verification|verify)\D{0,40}?(?<!\d)(\d{4,8})(?!\d)"
)
_CODE_BEFORE = re.compile(
    r"(?i)(?<!\d)(\d{4,8})(?!\d)\s*(?:is|=)?\s*(?:your|the)\s+(?:\w+\s+){0,2}(?:code|otp|passcode|pin)"
)
_SSN = re.compile(r"(?<!\d)(\d{3})[-. ](\d{2})[-. ](\d{4})(?!\d)")
# A bare 9 digits is an SSN only when it's called one (else it may be a
# routing number or anything else).
_SSN_NAMED = re.compile(r"(?i)\b(?:ssn|social security(?: number)?)\D{0,20}?(?<!\d)(\d{3})(\d{2})(\d{4})(?!\d)")
_NINE = re.compile(r"(?<!\d)\d{9}(?!\d)")
_ACCOUNT = re.compile(r"(?i)(?:account|acct)\D{0,15}?(?<!\d)(\d{6,17})(?!\d)")


@dataclass(frozen=True)
class Finding:
    kind: str       # received_code | card_number | ssn | routing_number | account_number | vault_secret
    start: int
    end: int
    label: str = ""  # e.g. vault entry name; never the secret itself

    def to_dict(self) -> dict:
        return {"kind": self.kind, "start": self.start, "end": self.end, "label": self.label}


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def aba_valid(digits: str) -> bool:
    """US routing number checksum."""
    if len(digits) != 9 or not digits.isdigit():
        return False
    d = [int(c) for c in digits]
    return (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])) % 10 == 0


def ssn_valid(area: str, group: str, serial: str) -> bool:
    return not (area in ("000", "666") or area.startswith("9") or group == "00" or serial == "0000")


def extract_codes(text: str) -> list[str]:
    """Pull verification codes out of an inbound message."""
    found = [m.group(1) for m in _CODE_AFTER.finditer(text)]
    found += [m.group(1) for m in _CODE_BEFORE.finditer(text)]
    return list(dict.fromkeys(found))


class SecretStore:
    """Checks received codes and vault values; persistent codes are stored as keyed digests."""

    def __init__(
        self,
        clock: Callable[[], float] = time.time,
        window: int = CODE_WINDOW_SECONDS,
        storage: WallStateStore | None = None,
    ):
        self._clock = clock
        self._window = window
        self._storage = storage
        self._codes: dict[str, float] = {}
        self._vault: dict[str, str] = {}
        self._lock = threading.Lock()

    def now(self) -> float:
        return self._clock()

    # ---- registration -------------------------------------------------
    def record_code(self, code: str) -> None:
        if self._storage:
            self._storage.record_code(code, self._clock())
            return
        with self._lock:
            self._codes[code] = self._clock()

    def add_vault_secret(self, name: str, value: str) -> None:
        if len(value) < 4:
            raise ValueError("vault values under 4 chars would match everything")
        with self._lock:
            self._vault[name] = value

    def active_codes(self) -> list[str]:
        now = self._clock()
        if self._storage:
            return []
        with self._lock:
            self._codes = {c: t for c, t in self._codes.items() if now - t < self._window}
            return list(self._codes)

    # ---- detection ----------------------------------------------------
    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._scan_codes(text)
        findings += self._scan_vault(text)
        findings += self._scan_cards(text)
        findings += self._scan_ssn(text)
        findings += self._scan_bank(text)
        return findings

    def _scan_codes(self, text: str) -> list[Finding]:
        """Exact match on the raw text first; then on the normalised digit stream
        (spaces, hyphens, number words, filler letters, fullwidth digits). A code hiding
        inside a longer number is also caught: we lean toward blocking."""
        out: list[Finding] = []
        stream = digit_stream(text)
        for code in self.active_codes():
            pat = re.compile(r"(?<!\d)" + re.escape(code) + r"(?!\d)")
            hits = list(pat.finditer(text))
            if hits:
                out += [Finding("received_code", m.start(), m.end()) for m in hits]
            elif code in stream:
                out.append(Finding("received_code", 0, len(text), label="obfuscated"))
        if self._storage and self._storage.matches_active_code(stream, self._clock(), self._window):
            out.append(Finding("received_code", 0, len(text), label="obfuscated"))
        return out

    def _scan_vault(self, text: str) -> list[Finding]:
        out: list[Finding] = []
        low = text.casefold()
        with self._lock:
            vault = dict(self._vault)
        for name, value in vault.items():
            start = low.find(value.casefold())
            while start != -1:
                out.append(Finding("vault_secret", start, start + len(value), label=name))
                start = low.find(value.casefold(), start + 1)
        return out

    def _scan_cards(self, text: str) -> list[Finding]:
        """Luhn check on the cleaned digits of each run ("4111 1111...", "4-1-1-1...",
        spelled-out digits). Token-aligned windows catch a card with extra digits
        appended. Runs are checked separately so unrelated numbers are never glued."""
        out: list[Finding] = []
        whole = nfkc(text) != text  # positions would not line up: flag the whole message
        for run in digit_runs(text):
            hit = None
            for i in range(len(run)):
                digits = ""
                for j in range(i, len(run)):
                    digits += run[j].digits
                    if len(digits) > 19:
                        break
                    if len(digits) >= 13 and luhn_valid(digits):
                        hit = (run[i].start, run[j].end)
                        break
                if hit:
                    break
            if hit:
                out.append(Finding("card_number", 0, len(text)) if whole else Finding("card_number", *hit))
        return out

    def _scan_ssn(self, text: str) -> list[Finding]:
        return [
            Finding("ssn", m.start(), m.end())
            for pattern in (_SSN, _SSN_NAMED)
            for m in pattern.finditer(text)
            if ssn_valid(*m.groups())
        ]

    def _scan_bank(self, text: str) -> list[Finding]:
        out = [Finding("routing_number", m.start(), m.end()) for m in _NINE.finditer(text) if aba_valid(m.group())]
        out += [Finding("account_number", m.start(1), m.end(1)) for m in _ACCOUNT.finditer(text)]
        return out
