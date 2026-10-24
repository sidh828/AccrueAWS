"""SQLite-backed append-only event log — the memory Cedar doesn't have.

See PRIMER.md Part 2. Rows are only ever inserted, never updated or deleted;
that's what makes the totals in aggregates.py trustworthy.
"""

import sqlite3

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    scope_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    cost_usd    REAL,
    decision    TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY'))
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_scope_id ON events (scope_id);

CREATE TRIGGER IF NOT EXISTS prevent_event_updates
BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_event_deletes
BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;

-- Cross-session scopes: scope_id on events is the durable identity that
-- outlives one session_id (see NOTES.md "Ideas"). overrides is the only
-- thing that can un-trip breaker.is_tripped for a scope - a human
-- explicitly saying "let it keep going" after a DENY, logged the same
-- append-only way as everything else.
CREATE TABLE IF NOT EXISTS overrides (
    id            INTEGER PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    scope_id      TEXT NOT NULL,
    authorized_by TEXT NOT NULL,
    reason        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_overrides_scope_id ON overrides (scope_id);

CREATE TRIGGER IF NOT EXISTS prevent_override_updates
BEFORE UPDATE ON overrides
BEGIN
    SELECT RAISE(ABORT, 'overrides are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_override_deletes
BEFORE DELETE ON overrides
BEGIN
    SELECT RAISE(ABORT, 'overrides are append-only');
END;
"""


def connect(db_path="ledger.db"):
    """Open a ledger database and create its schema if needed."""
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def insert_event(conn, timestamp, session_id, action, resource, cost_usd, decision,
                  scope_id=None):
    """Append one event and return its database id.

    The caller owns the transaction. This is important for authorization:
    reading the aggregates and recording the decision must commit atomically.

    `scope_id` is the durable cross-session identity this event rolls up
    under (see aggregates.cumulative_cost_for_scope). Defaults to
    session_id, so a caller with no separate scope concept yet just scopes
    to itself - existing single-session behavior is unchanged.
    """
    if scope_id is None:
        scope_id = session_id
    cursor = conn.execute(
        "INSERT INTO events "
        "(timestamp, session_id, scope_id, action, resource, cost_usd, decision) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (timestamp, session_id, scope_id, action, resource, cost_usd, decision),
    )
    return cursor.lastrowid


def list_events(conn, session_id=None, scope_id=None):
    """Return events in append order, optionally filtered by session and/or
    scope."""
    query = ("SELECT id, timestamp, session_id, scope_id, action, resource, "
             "cost_usd, decision FROM events")
    conditions = []
    params = []
    if session_id is not None:
        conditions.append("session_id = ?")
        params.append(session_id)
    if scope_id is not None:
        conditions.append("scope_id = ?")
        params.append(scope_id)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id"
    return conn.execute(query, params).fetchall()


def insert_override(conn, timestamp, scope_id, authorized_by, reason):
    """Record express human permission for a scope to resume after the
    circuit breaker trips it (see breaker.is_tripped). Append-only, same as
    events - this is the only way to un-trip a scope.
    """
    cursor = conn.execute(
        "INSERT INTO overrides (timestamp, scope_id, authorized_by, reason) "
        "VALUES (?, ?, ?, ?)",
        (timestamp, scope_id, authorized_by, reason),
    )
    return cursor.lastrowid


def list_overrides(conn, scope_id=None):
    """Return overrides in append order, optionally limited to one scope."""
    if scope_id is None:
        return conn.execute(
            "SELECT id, timestamp, scope_id, authorized_by, reason "
            "FROM overrides ORDER BY id"
        ).fetchall()

    return conn.execute(
        "SELECT id, timestamp, scope_id, authorized_by, reason "
        "FROM overrides WHERE scope_id = ? ORDER BY id",
        (scope_id,),
    ).fetchall()
