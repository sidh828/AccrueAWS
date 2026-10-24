"""Aggregate queries — the three things Cedar can't do, done in SQL.

Only rows with decision = 'ALLOW' count. A DENYed attempt never happened,
so it must not count toward the next check — otherwise a burst of rejected
requests would itself push a session over budget.
"""

# home_scope lives in ledger.py now (insert_event stores it); it's still
# importable from here, where authorize.py has always found it.
from .ledger import home_scope, normalize_scope


def cumulative_cost(conn, session_id):
    row = conn.execute(
        "SELECT COALESCE(SUM(amount_cents), 0) FROM events "
        "WHERE session_id = ? AND decision = 'ALLOW'",
        (session_id,),
    ).fetchone()
    return row[0]


def action_count(conn, session_id):
    row = conn.execute(
        "SELECT COUNT(*) FROM events WHERE session_id = ? AND decision = 'ALLOW'",
        (session_id,),
    ).fetchone()
    return row[0]


def distinct_resource_count(conn, session_id):
    row = conn.execute(
        "SELECT COUNT(DISTINCT resource) FROM events "
        "WHERE session_id = ? AND decision = 'ALLOW'",
        (session_id,),
    ).fetchone()
    return row[0]


# --- Cross-session scopes ---------------------------------------------
#
# A session_id is one conversation. A scope_id is the thing that outlives
# it - the same agent/user across many sessions. See NOTES.md "Ideas" for
# the full design writeup; these two are the pieces authorize.py needs to
# actually use a scope instead of a lone session.

def _scope_filter(scope_id):
    """WHERE clause and params selecting a normalized scope_id plus
    everything nested under it.

    - "" is the root: every row.
    - A home ("agent-a", no "/") is an indexed equality on the `home`
      column. That's the query authorize.py runs on every request.
    - A deeper path ("agent-a/task-x") is the scope itself, or anything in
      the half-open range ["agent-a/task-x/", "agent-a/task-x0"), since "0"
      is the character right after "/". That's exactly the strings starting
      with the prefix, compared byte for byte: no LIKE, so no wildcards to
      escape and no case folding, and the scope_id index can serve it.
    """
    if scope_id == "":
        return "1", []
    if "/" not in scope_id:
        return "home = ?", [scope_id]
    return ("(scope_id = ? OR (scope_id >= ? AND scope_id < ?))",
            [scope_id, scope_id + "/", scope_id + "0"])


def cumulative_cost_for_scope(conn, scope_id, since=None, category=None):
    """Like cumulative_cost, but rolled up across every session under one
    durable scope_id, optionally windowed to only events at or after
    `since`.

    A scope_id can be a flat id ("agent-a") or a filesystem-shaped path
    ("agent-a/task-checkout-flow") - see NOTES.md "Scope paths". Either
    way this counts the scope itself plus anything nested under it as a
    "/"-separated child, so calling this with "agent-a" rolls up every
    task under that agent, and calling it with the empty string "" rolls
    up every scope there is (the root level).

    Only decision = 'ALLOW' rows count, same reason as cumulative_cost
    above: a DENYed attempt never happened.

    `since` must be in ledger.utc_timestamp's format: the comparison is on
    strings. `category`, when given, counts only that category.

    An approved hold counts from its approval row (see ledger.SCHEMA); the
    HOLD row itself never does.
    """
    where, params = _scope_filter(normalize_scope(scope_id))
    query = ("SELECT COALESCE(SUM(amount_cents), 0) FROM events "
             f"WHERE {where} AND decision = 'ALLOW'")
    if since is not None:
        query += " AND timestamp >= ?"
        params.append(since)
    if category is not None:
        query += " AND category = ?"
        params.append(category)

    row = conn.execute(query, params).fetchone()
    return row[0]


def last_event_for_scope(conn, scope_id):
    """The single most recent event for this scope_id or anything nested
    under it (same rollup as cumulative_cost_for_scope), or None if it has
    none yet. breaker.is_tripped needs this to check whether the *last*
    thing that happened anywhere in a scope was a DENY - a DENY in one task
    has to trip its siblings too, or the agent just moves to another task.
    """
    where, params = _scope_filter(normalize_scope(scope_id))
    return conn.execute(
        "SELECT id, timestamp, session_id, scope_id, action, resource, "
        f"amount_cents, decision FROM events WHERE {where} "
        "ORDER BY id DESC LIMIT 1",
        params,
    ).fetchone()


# --- Family payments ----------------------------------------------------
#
# What authorize.authorize_payment needs besides totals. All of these are
# per home (the person), so they share the (home, ...) indexes.

def has_paid(conn, home, payee):
    """Whether anything was ever allowed from this person to this payee.
    False means the next payment is a first payment to someone new."""
    return conn.execute(
        "SELECT 1 FROM events WHERE home = ? AND payee = ? AND decision = 'ALLOW' "
        "LIMIT 1",
        (normalize_scope(home), payee),
    ).fetchone() is not None


def last_payment(conn, home, payee, since):
    """The most recent amount allowed from this person to this payee at or
    after `since`, or None."""
    row = conn.execute(
        "SELECT amount_cents FROM events "
        "WHERE home = ? AND payee = ? AND decision = 'ALLOW' AND timestamp >= ? "
        "ORDER BY id DESC LIMIT 1",
        (normalize_scope(home), payee, since),
    ).fetchone()
    return None if row is None else row[0]


def denials_since(conn, home, since):
    """How many payments the guard itself denied for this person at or after
    `since`, not counting any from before the person's last override (see
    ledger.insert_override). A family member denying a held payment isn't
    counted: only the guard's own denials trip the breaker."""
    home = normalize_scope(home)
    row = conn.execute(
        "SELECT COUNT(*) FROM events "
        "WHERE home = ? AND decision = 'DENY' AND resolves IS NULL "
        "AND timestamp >= ? AND id > ("
        "    SELECT COALESCE(MAX(after_event_id), 0) FROM overrides WHERE scope_id = ?"
        ")",
        (home, since, home),
    ).fetchone()
    return row[0]
