"""The glue between the append-only ledger and Cedar.

Cedar stays exactly as stateless as it's designed to be: it only ever sees a
`cumulative_cost` number that already includes the pending action. All the
"memory" lives in ledger.py / aggregates.py — never inside a policy.

The check (read the running total) and the act (log this attempt) happen
inside one SQLite transaction opened with BEGIN IMMEDIATE, so two concurrent
requests can't both read the same stale total and both get approved. That
race — not Cedar's statelessness itself — is the actual loophole this file
exists to close. See PRIMER.md §1.4.
"""

import json
import math
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import aggregates, breaker, ledger

POLICY_PATH = Path(__file__).parent / "policies" / "budget.cedar"


def _entity_uid(entity_type, entity_id):
    """Build a Cedar entity UID like Account::"acct-1234" from an
    untrusted id.

    The id sits inside a Cedar string literal, so a raw `"` or `\\` in it
    would end the literal early or start an escape - `x" ...` stops being one
    id. Today that only makes the request fail to parse, because no policy
    reads principal or resource, but it would become a bypass the moment one
    does. Quotes and backslashes are escaped; control characters, which
    Cedar won't accept in an id at all, are rejected as malformed input.
    """
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in entity_id):
        raise ValueError(
            f"{entity_type} id must not contain control characters, got {entity_id!r}"
        )
    escaped = entity_id.replace("\\", "\\\\").replace('"', '\\"')
    return f'{entity_type}::"{escaped}"'


def _ask_cedar(principal, action, resource, context):
    """Shell out to the `cedar` CLI and return "ALLOW" or "DENY".

    Cedar does not abort when a policy errors while being evaluated (e.g. a
    context attribute typo'd in a `when` clause, or a request built with a
    different context shape than the policy expects). It drops just that
    policy and keeps going with whatever's left - so a `forbid` that
    references a bad attribute can be silently skipped and a `permit`
    elsewhere wins by default. The CLI still exits 0 for that case; the only
    sign anything went wrong is extra text on stdout after the decision
    word. A clean decision is *only* "ALLOW" or "DENY" - anything else means
    a policy errored and the decision can't be trusted, so this raises
    instead of returning it. `cedar validate` (run in CI against
    budget.cedarschema) is what's supposed to catch these before they ship;
    this check is the last line of defense if one gets through anyway.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        context_path = Path(tmpdir) / "context.json"
        entities_path = Path(tmpdir) / "entities.json"
        context_path.write_text(json.dumps(context))
        entities_path.write_text("[]")

        result = subprocess.run(
            [
                "cedar",
                "authorize",
                "--policies", str(POLICY_PATH),
                "--entities", str(entities_path),
                "--principal", principal,
                "--action", action,
                "--resource", resource,
                "--context", str(context_path),
            ],
            capture_output=True,
            text=True,
        )
        # The CLI exits 0 for ALLOW and 2 for DENY - both are real decisions.
        # Anything else (bad policy file, malformed context, ...) is a tool
        # failure and must not be silently treated as a DENY decision.
        if result.returncode not in (0, 2):
            raise RuntimeError(f"cedar authorize failed: {result.stderr}")

        decision = result.stdout.strip()
        if decision not in ("ALLOW", "DENY"):
            raise RuntimeError(
                "cedar authorize returned more than a clean decision - a "
                "policy likely errored while evaluating and was silently "
                f"dropped, so this can't be trusted: {decision!r}"
            )
        return decision


def authorize_transfer(conn, session_id, resource, amount_usd, scope_id=None):
    """Ask "can this transfer happen?", accounting for everything this
    scope has already spent - across every session under it, not just this
    one. Returns "ALLOW" or "DENY" and logs the attempt either way — only
    ALLOWed amounts count toward future totals.

    `scope_id` is the durable cross-session identity to check and log this
    event under (see aggregates.cumulative_cost_for_scope - it rolls up a
    flat scope_id or a filesystem-shaped path the same way). Defaults to
    session_id, so a caller with no separate scope concept yet behaves
    exactly as before - a lone session is just a scope of one. A session_id
    containing "/" can't be used that way (see below), so pass scope_id
    explicitly for those.

    The budget and the breaker are enforced at the scope's *home* - its
    first path segment - not at the full path: "agent-a/task-x" and
    "agent-a/task-y" share one budget, and a DENY in either trips both.
    The event itself is still logged under the full path. This assumes the
    integrator, not the agent, sets the home segment; an agent that can
    choose its own home can still get a fresh budget per home.

    `amount_usd` must be a finite, non-negative number. A negative amount
    would be ALLOWed (it only lowers prospective_total) and then logged as
    an ALLOW row that subtracts from every future cumulative total - a
    -$50,000 "transfer" buys $50,000 of extra headroom. That's malformed
    input, not a decision, so it raises rather than returning DENY.
    """
    if not math.isfinite(amount_usd) or amount_usd < 0:
        raise ValueError(
            f"amount_usd must be a finite, non-negative number, got {amount_usd!r}"
        )

    # Built before the transaction opens, so a malformed id raises without
    # logging anything - same as a bad amount.
    principal = _entity_uid("Session", session_id)
    account = _entity_uid("Account", resource)

    if not scope_id:
        # A session_id is opaque - nothing says its "/" means a path. Used as
        # a scope, "user/123" would get home "user" and silently share one
        # budget and breaker with "user/456". Refuse instead of guessing.
        if "/" in session_id:
            raise ValueError(
                f"session_id {session_id!r} contains '/', so it can't double as "
                "a scope_id - pass scope_id explicitly"
            )
        scope_id = session_id
    home = aggregates.home_scope(scope_id)
    if not home:
        # "/x" has an empty home, which would roll up to the root - every
        # agent's spend counted against this one request.
        raise ValueError(f"scope_id must start with a home segment, got {scope_id!r}")

    conn.execute("BEGIN IMMEDIATE")
    try:
        timestamp = datetime.now(timezone.utc).isoformat()

        # A tripped home doesn't get to ask again, no matter how small the
        # amount, how much cumulative-cost headroom remains, or which task
        # under it is asking - that's the whole point of the breaker (see
        # src/breaker.py). Only an explicit ledger.insert_override logged
        # against the home resets it.
        if breaker.is_tripped(conn, home):
            ledger.insert_event(
                conn, timestamp, session_id, "transfer", resource, amount_usd,
                "DENY", scope_id=scope_id,
            )
            conn.commit()
            return "DENY"

        already_spent = aggregates.cumulative_cost_for_scope(conn, home)
        prospective_total = already_spent + amount_usd

        decision = _ask_cedar(
            principal,
            'Action::"transfer"',
            account,
            # Cedar's JSON format has no float type - only Long integers -
            # so `cumulative_cost` (a REAL column, always a float in Python)
            # has to be rounded to whole dollars before it crosses the CLI
            # boundary, or the request is rejected outright as malformed.
            # Rounded *up*, never to nearest: round() turned 10000.4 into
            # 10000, which passes `> 10000`. Snapping to cents first keeps
            # float drift (100,000 x $0.10 sums to 10000.000000018848) from
            # being rounded up into a DENY for a total that's exactly at
            # the cap. The cost: an overage under half a cent (10000.004)
            # still snaps back to 10000 and is ALLOWed.
            {"cumulative_cost": math.ceil(round(prospective_total, 2))},
        )

        ledger.insert_event(
            conn, timestamp, session_id, "transfer", resource, amount_usd,
            decision, scope_id=scope_id,
        )
        conn.commit()
        return decision
    except Exception:
        conn.rollback()
        raise
