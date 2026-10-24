"""Circuit breaker for cross-session scopes.

The 50x-$9,999 pattern (PRIMER.md 1.4) is already closed by
aggregates.cumulative_cost: DENYs don't count, so retrying the *same*
amount keeps failing once the running total is over budget. This solves a
different problem - an agent (or attacker) that doesn't retry the same
amount, but *searches* for one that slips under: try $9,999, get denied,
try $500, try $50, try $1... Cumulative cost alone can't see that pattern,
because each smaller request might individually still fit.

The rule this file implements instead: once a scope has been denied, it's
done - every further request for that scope auto-DENYs, and Cedar isn't
even asked - until a human appends an explicit override (see
ledger.insert_override). authorize.py should call is_tripped() before its
existing cumulative_cost check, so a tripped scope never even gets that
far.
"""

from . import aggregates, ledger


def is_tripped(conn, scope_id):
    """True if the most recent event for this scope, or anything nested
    under it, was a DENY with no override logged after it. Overrides only
    count when logged against this exact scope_id - authorize.py calls this
    with the home ("agent-a"), so that's where an override has to go.
    """
    last = aggregates.last_event_for_scope(conn, scope_id)
    if last is None:
        return False

    # column order from aggregates.last_event_for_scope's SELECT:
    # id, timestamp, session_id, scope_id, action, resource, cost_usd, decision
    _, deny_timestamp, _, _, _, _, _, decision = last
    if decision != "DENY":
        return False

    return not any(
        override_timestamp > deny_timestamp
        for _, override_timestamp, _, _, _ in ledger.list_overrides(conn, scope_id)
    )
