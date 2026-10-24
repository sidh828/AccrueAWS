"""Signed delegation tokens: who an agent is acting for, and how much it may
spend - proven, not claimed.

CLAUDE.md: "Sub-agents carry signed tokens derived from their parent's; a
child's budget can only be smaller." The scheme is a macaroon - a chain of
HMACs:

    sig_0 = HMAC(key, root caveat)            minted by the guard for Mom
    sig_i = HMAC(sig_{i-1}, caveat_i)          added by whoever holds the token

Anyone holding a token can add a caveat (attenuate) - name the next agent,
a smaller budget, fewer tools, an expiry - because the next signature only
needs the current one. Nobody can remove or loosen a caveat: that would
mean recomputing an earlier signature, which needs the guard's key or a
signature the holder never saw. The guard rebuilds the chain from its key
and enforces every caveat, so the tightest one wins and adding a bigger
budget changes nothing.

Caveats (JSON objects, in order):
    {"person": "mom"}              the root, minted by the guard
    {"agent": "bills-agent"}       the next link of the chain
    {"day_cents": 30000}           this branch's 24-hour budget
    {"tools": ["pay_bill"]}        the tools this branch may use
    {"expires": "2026-10-25T10:00:00.000000Z"}

    python3 -m guard.tokens mint --person mom --agent bills-agent --day 50000
        (the key comes from ACCRUE_TOKEN_KEY; the agent gets the printed token)

A token is base64url(JSON {"caveats": [...], "sig": hex}).
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field

from . import ledger

KNOWN_CAVEATS = {"person", "agent", "day_cents", "tools", "expires"}


class TokenError(ValueError):
    """The token is malformed, forged, altered or expired."""


def _canonical(caveat):
    return json.dumps(caveat, sort_keys=True, separators=(",", ":")).encode()


def _sign(key_or_sig, caveat):
    return hmac.new(key_or_sig, _canonical(caveat), hashlib.sha256).digest()


def _encode(caveats, sig):
    raw = json.dumps({"caveats": caveats, "sig": sig.hex()}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode(token):
    try:
        raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
        body = json.loads(raw)
        caveats, sig = body["caveats"], bytes.fromhex(body["sig"])
    except (ValueError, KeyError, TypeError) as err:
        raise TokenError(f"malformed token: {err}") from None
    if not isinstance(caveats, list) or not all(isinstance(c, dict) for c in caveats):
        raise TokenError("malformed token: caveats must be a list of objects")
    return caveats, sig


def _check_caveat(caveat):
    if len(caveat) != 1 or next(iter(caveat)) not in KNOWN_CAVEATS:
        raise TokenError(f"unknown caveat {caveat!r}")
    (name, value), = caveat.items()
    ok = {
        "person": isinstance(value, str) and value and "/" not in value,
        "agent": isinstance(value, str) and value and "/" not in value,
        "day_cents": type(value) is int and value >= 0,
        "tools": isinstance(value, list) and all(isinstance(t, str) for t in value),
        "expires": isinstance(value, str),
    }[name]
    if not ok:
        raise TokenError(f"bad caveat {caveat!r}")


def mint(key, person, agent=None, day_cents=None, tools=None):
    """A root token for `person`, signed with the guard's key, optionally
    already naming the first agent and narrowing it."""
    if not key:
        raise ValueError("minting needs the guard's token key")
    key = key.encode() if isinstance(key, str) else key
    root = {"person": person}
    _check_caveat(root)
    token = _encode([root], _sign(key, root))
    if agent is not None:
        token = attenuate(token, {"agent": agent})
    if day_cents is not None:
        token = attenuate(token, {"day_cents": day_cents})
    if tools is not None:
        token = attenuate(token, {"tools": sorted(tools)})
    return token


def attenuate(token, caveat):
    """The same token with one more caveat. Needs no key: anyone holding a
    token can narrow it, nobody can widen it."""
    _check_caveat(caveat)
    if "person" in caveat:
        raise TokenError("only the guard mints a root")
    caveats, sig = _decode(token)
    return _encode(caveats + [caveat], _sign(sig, caveat))


@dataclass(frozen=True)
class Delegation:
    """What a verified token allows. `chain` is the person and every agent
    link, in order. `budgets` are (depth, cents): the 24-hour budget for the
    branch chain[:depth + 1]. `tools` is None when no caveat narrows them."""
    person: str
    chain: tuple
    budgets: tuple = field(default_factory=tuple)
    tools: frozenset = None
    expires: str = None


def verify(key, token, now_timestamp=None):
    """Rebuild the token's signature chain from the guard's key and return
    its Delegation, or raise TokenError if anything doesn't check out."""
    if not key:
        raise TokenError("no token key configured")
    key = key.encode() if isinstance(key, str) else key
    caveats, sig = _decode(token)
    if not caveats or set(caveats[0]) != {"person"}:
        raise TokenError("a token must start with its person")
    expected = key
    for caveat in caveats:
        _check_caveat(caveat)
        expected = _sign(expected, caveat)
    if not hmac.compare_digest(expected, sig):
        raise TokenError("signature doesn't match: the token was altered or forged")

    person = caveats[0]["person"].lower()
    chain, budgets, tools, expires = [person], [], None, None
    for caveat in caveats[1:]:
        (name, value), = caveat.items()
        if name == "person":
            raise TokenError("a token has one person")
        if name == "agent":
            chain.append(value.lower())
        elif name == "day_cents":
            budgets.append((len(chain) - 1, value))
        elif name == "tools":
            narrowed = frozenset(t.lower() for t in value)
            tools = narrowed if tools is None else tools & narrowed
        elif name == "expires":
            expires = value if expires is None else min(expires, value)
    now_timestamp = now_timestamp or ledger.utc_timestamp()
    if expires is not None and now_timestamp >= expires:
        raise TokenError(f"token expired at {expires}")
    return Delegation(person, tuple(chain), tuple(budgets), tools, expires)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Mint or narrow a delegation token")
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("mint", help="a root token, signed with ACCRUE_TOKEN_KEY")
    m.add_argument("--person", required=True)
    m.add_argument("--agent")
    m.add_argument("--day", type=int, help="24-hour budget in cents")
    m.add_argument("--tools", help="comma-separated")
    n = sub.add_parser("narrow", help="add caveats to a token (no key needed)")
    n.add_argument("token")
    n.add_argument("--agent")
    n.add_argument("--day", type=int)
    n.add_argument("--tools")
    args = parser.parse_args(argv)
    tools = args.tools.split(",") if args.tools else None
    if args.command == "mint":
        print(mint(os.environ.get("ACCRUE_TOKEN_KEY"), args.person, args.agent, args.day, tools))
        return
    token = args.token
    for caveat in ({"agent": args.agent} if args.agent else None,
                   {"day_cents": args.day} if args.day is not None else None,
                   {"tools": sorted(tools)} if tools else None):
        if caveat:
            token = attenuate(token, caveat)
    print(token)


if __name__ == "__main__":
    main()
