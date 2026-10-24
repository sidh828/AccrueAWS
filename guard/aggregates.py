"""Aggregate queries — the three things Cedar can't do, done in SQL.

Only rows with decision = 'ALLOW' count. A DENYed attempt never happened,
so it must not count toward the next check — otherwise a burst of rejected
requests would itself push a session over budget.
"""


def cumulative_cost(conn, session_id):
    row = conn.execute(
        "SELECT COALESCE(SUM(cost_usd), 0) FROM events "
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

def _escape_like(value):
    """Escape a string for safe use inside a SQL LIKE pattern.

    % and _ are LIKE wildcards; without escaping them, a scope_id that
    happens to contain one (e.g. "a_b") would match more than its own
    literal name when used as a prefix (e.g. "a_b/..." would also match
    "aXb/..."). Must be paired with `ESCAPE '\\'` in the query.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def cumulative_cost_for_scope(conn, scope_id, since=None):
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
    """
    if scope_id == "":
        query = "SELECT COALESCE(SUM(cost_usd), 0) FROM events WHERE decision = 'ALLOW'"
        params = []
    else:
        query = (
            "SELECT COALESCE(SUM(cost_usd), 0) FROM events "
            "WHERE decision = 'ALLOW' "
            "AND (scope_id = ? OR scope_id LIKE ? ESCAPE '\\')"
        )
        params = [scope_id, _escape_like(scope_id) + "/%"]

    if since is not None:
        query += " AND timestamp >= ?"
        params.append(since)

    row = conn.execute(query, params).fetchone()
    return row[0]


def home_scope(scope_id):
    """The "home" segment of a scope path - "agent-a" for both "agent-a"
    and "agent-a/task-checkout-flow". authorize.py enforces the budget and
    the breaker here rather than at the full path, because the task segment
    is free-form: if each task had its own budget, inventing a new task
    name would buy a fresh $10,000 every time.
    """
    return scope_id.split("/", 1)[0]


def last_event_for_scope(conn, scope_id):
    """The single most recent event for this scope_id or anything nested
    under it (same rollup as cumulative_cost_for_scope), or None if it has
    none yet. breaker.is_tripped needs this to check whether the *last*
    thing that happened anywhere in a scope was a DENY - a DENY in one task
    has to trip its siblings too, or the agent just moves to another task.
    """
    return conn.execute(
        "SELECT id, timestamp, session_id, scope_id, action, resource, "
        "cost_usd, decision FROM events "
        "WHERE scope_id = ? OR scope_id LIKE ? ESCAPE '\\' "
        "ORDER BY id DESC LIMIT 1",
        (scope_id, _escape_like(scope_id) + "/%"),
    ).fetchone()
