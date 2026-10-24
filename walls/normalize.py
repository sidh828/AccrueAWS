"""Text normalisation shared by every wall check (and the Tier 2 disclosure caps).

Goal: "4 2 7 1 9 3", "4-2-7-1-9-3", "four two seven one nine three",
"double four two one nine three" and fullwidth "４２７１９３" all reduce to the same
digit string, deterministically, so an exact-match secret check can't be dodged by
formatting. No AI, no fuzzy matching.

Two views of a text:
  digit_stream(text) - every digit and number word in order, everything else dropped.
                       Used for verification codes (a block-leaning check).
  digit_runs(text)   - maximal runs of digit tokens separated only by punctuation or
                       whitespace. Used for card numbers, where the Luhn check must run
                       on one number and not on unrelated digits glued together.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

NUMBER_WORDS = {
    "zero": "0", "oh": "0", "one": "1", "two": "2", "three": "3", "four": "4",
    "five": "5", "six": "6", "seven": "7", "eight": "8", "nine": "9",
}
MULTIPLIERS = {"double": 2, "triple": 3}
_TOKEN = re.compile(r"[^\W\d_]+|\d+")


@dataclass(frozen=True)
class Token:
    digits: str | None  # None = an ordinary word that is not a number
    start: int
    end: int


def nfkc(text: str) -> str:
    """Fold fullwidth and other lookalike digits to ASCII."""
    return unicodedata.normalize("NFKC", text)


def tokens(text: str) -> list[Token]:
    text = nfkc(text)
    raw = [(m.group().lower(), m.start(), m.end()) for m in _TOKEN.finditer(text)]

    def digits_of(word: str) -> str | None:
        return word if word.isdigit() else NUMBER_WORDS.get(word)

    out: list[Token] = []
    i = 0
    while i < len(raw):
        word, s, e = raw[i]
        if word in MULTIPLIERS and i + 1 < len(raw) and digits_of(raw[i + 1][0]):
            d = digits_of(raw[i + 1][0]) * MULTIPLIERS[word]
            out.append(Token(d, s, raw[i + 1][2]))
            i += 2
            continue
        out.append(Token(digits_of(word), s, e))
        i += 1
    return out


def digit_stream(text: str) -> str:
    return "".join(t.digits for t in tokens(text) if t.digits)


def digit_runs(text: str) -> list[list[Token]]:
    runs: list[list[Token]] = []
    cur: list[Token] = []
    for t in tokens(text):
        if t.digits:
            cur.append(t)
        elif cur:
            runs.append(cur)
            cur = []
    if cur:
        runs.append(cur)
    return runs
