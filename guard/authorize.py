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
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import aggregates, breaker, ledger

POLICY_PATH = Path(__file__).parent / "policies" / "budget.cedar"

# Spending older than this no longer counts toward the budget. Rolling, not
# calendar: with a midnight reset, a full budget at 11:59 PM and another at
# 12:01 AM would both fit. Without any window, a home that spent its budget
# once was locked out forever.
BUDGET_WINDOW = timedelta(hours=24)

# The Cedar CLI to run. Overridable so a demo or a test can point it at a
# binary that hangs or is missing and show the guard failing closed.
CEDAR_BIN = os.environ.get("ACCRUE_CEDAR_BIN", "cedar")

# A clean Cedar call takes a few milliseconds. The call runs while
# authorize_transfer holds the ledger's write lock, so a hung Cedar with no
# timeout blocked every other request until it got "database is locked".
CEDAR_TIMEOUT_SECONDS = 2.0

# $10 billion. Anything bigger is a bug or an attack, and the running total
# has to stay well inside Cedar's 64-bit Long.
MAX_AMOUNT_CENTS = 10**12


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


def _ask_cedar(principal, action, resource, context, policy_path=None):
    """Shell out to the `cedar` CLI and return "ALLOW" or "DENY", under
    `policy_path` (default: POLICY_PATH).

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

        try:
            result = subprocess.run(
                [
                    CEDAR_BIN,
                    "authorize",
                    "--policies", str(policy_path or POLICY_PATH),
                    "--entities", str(entities_path),
                    "--principal", principal,
                    "--action", action,
                    "--resource", resource,
                    "--context", str(context_path),
                ],
                capture_output=True,
                text=True,
                timeout=CEDAR_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            # run() has already killed the process. Raising rolls back
            # authorize_transfer's transaction and releases the lock;
            # nothing is logged and nothing is allowed.
            raise RuntimeError(
                f"cedar authorize timed out after {CEDAR_TIMEOUT_SECONDS}s"
            ) from None
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


def authorize_transfer(conn, session_id, resource, amount_cents, scope_id=None,
                       request_id=None, policy_path=None):
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

    The budget covers what the home spent in the last BUDGET_WINDOW. The
    breaker has no window: once tripped, it stays tripped until an override.

    The budget and the breaker are enforced at the scope's *home* - its
    first path segment - not at the full path: "agent-a/task-x" and
    "agent-a/task-y" share one budget, and a DENY in either trips both.
    The event itself is still logged under the full path. This assumes the
    integrator, not the agent, sets the home segment; an agent that can
    choose its own home can still get a fresh budget per home.

    `amount_cents` must be a non-negative int, at most MAX_AMOUNT_CENTS.
    Money is integer cents everywhere (CLAUDE.md), so a float, a bool or a
    string is malformed input, not a decision: it raises rather than
    returning DENY, and nothing is logged. A negative amount would be
    ALLOWed (it only lowers prospective_total) and then logged as an ALLOW
    row that subtracts from every future total - a -$50,000 "transfer"
    buys $50,000 of extra headroom.

    `request_id` makes a retry safe. If an event with this request_id is
    already in the ledger, its decision is returned and nothing new is
    logged, so an agent that times out and asks again isn't counted (or
    paid) twice. Reusing a request_id for a different request raises.

    `policy_path` is the Cedar policy to decide under (default:
    POLICY_PATH), so a draft policy can be checked beside the live one.
    """
    # type() rather than isinstance(): bool is a subclass of int, and True
    # is not one cent.
    if type(amount_cents) is not int or not 0 <= amount_cents <= MAX_AMOUNT_CENTS:
        raise ValueError(
            "amount_cents must be an int between 0 and "
            f"{MAX_AMOUNT_CENTS}, got {amount_cents!r}"
        )
    if request_id is not None and (type(request_id) is not str or not request_id):
        raise ValueError(f"request_id must be a non-empty string, got {request_id!r}")

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
        # Checked inside the lock, so two copies of one request racing each
        # other can't both miss the first one's row.
        if request_id is not None:
            prior = ledger.find_by_request_id(conn, request_id)
            if prior is not None:
                _, p_session, p_scope, p_resource, p_amount, p_decision = prior
                if (p_session, p_scope, p_resource, p_amount) != (
                    session_id, ledger.normalize_scope(scope_id), resource, amount_cents
                ):
                    raise ValueError(
                        f"request_id {request_id!r} was already used for a "
                        "different request"
                    )
                conn.rollback()
                return p_decision

        now = datetime.now(timezone.utc)
        timestamp = ledger.utc_timestamp(now)

        # A tripped home doesn't get to ask again, no matter how small the
        # amount, how much cumulative-cost headroom remains, or which task
        # under it is asking - that's the whole point of the breaker (see
        # guard/breaker.py). Only an explicit ledger.insert_override logged
        # against the home resets it.
        if breaker.is_tripped(conn, home):
            ledger.insert_event(
                conn, timestamp, session_id, "transfer", resource, amount_cents,
                "DENY", scope_id=scope_id, request_id=request_id,
            )
            conn.commit()
            return "DENY"

        already_spent = aggregates.cumulative_cost_for_scope(
            conn, home, since=ledger.utc_timestamp(now - BUDGET_WINDOW)
        )

        # Integer cents in, integer cents to Cedar: its JSON has only Long
        # integers, so there's no rounding left to get wrong.
        decision = _ask_cedar(
            principal,
            'Action::"transfer"',
            account,
            {"cumulative_cost": already_spent + amount_cents},
            policy_path=policy_path,
        )

        ledger.insert_event(
            conn, timestamp, session_id, "transfer", resource, amount_cents,
            decision, scope_id=scope_id, request_id=request_id,
        )
        conn.commit()
        return decision
    except Exception:
        conn.rollback()
        raise
