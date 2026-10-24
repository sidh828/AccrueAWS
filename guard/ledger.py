"""SQLite-backed append-only event log — the memory Cedar doesn't have.

See PRIMER.md Part 2. Rows are only ever inserted, never updated or deleted;
that's what makes the totals in aggregates.py trustworthy.
"""

import sqlite3
from datetime import datetime, timezone

# `home` is the first segment of scope_id (see home_scope), stored so the
# budget and breaker queries in aggregates.py are an indexed equality
# lookup instead of a scan of every row ever logged. (home, timestamp)
# serves the windowed total; (home) serves "last event" in id order.
SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    session_id  TEXT NOT NULL,
    scope_id    TEXT NOT NULL,
    home        TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    amount_cents INTEGER NOT NULL
                CHECK (typeof(amount_cents) = 'integer' AND amount_cents >= 0),
    decision    TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY')),
    request_id  TEXT UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_scope_id ON events (scope_id);
CREATE INDEX IF NOT EXISTS idx_events_home ON events (home);
CREATE INDEX IF NOT EXISTS idx_events_home_time ON events (home, timestamp);

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
-- append-only way as everything else. after_event_id is the last events.id
-- at the moment the override was written: it's what orders an override
-- against a DENY, not the timestamp, which is only kept for the audit.
CREATE TABLE IF NOT EXISTS overrides (
    id             INTEGER PRIMARY KEY,
    timestamp      TEXT NOT NULL,
    scope_id       TEXT NOT NULL,
    authorized_by  TEXT NOT NULL,
    reason         TEXT NOT NULL,
    after_event_id INTEGER NOT NULL
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


def normalize_scope(scope_id):
    """The one spelling of a scope that's stored and queried: lowercase.

    The budget and the breaker are keyed on the scope's home, so "Mom" and
    "mom" have to be the same person. Before this, an exact match treated
    them as two budgets while SQLite's case-insensitive LIKE rolled some of
    one into the other. Everything that writes or reads a scope_id goes
    through here.
    """
    return scope_id.lower()


def home_scope(scope_id):
    """The "home" segment of a scope path - "agent-a" for both "agent-a"
    and "agent-a/task-checkout-flow". authorize.py enforces the budget and
    the breaker here rather than at the full path, because the task segment
    is free-form: if each task had its own budget, inventing a new task
    name would buy a fresh $10,000 every time.
    """
    return scope_id.split("/", 1)[0]


def utc_timestamp(moment=None):
    """The one timestamp format the ledger writes: UTC, fixed width, "Z".

    Time windows compare timestamps as strings, which only orders them
    correctly when every one has the same shape. isoformat() doesn't
    guarantee that: it drops the microseconds when they're zero and writes
    "+00:00" where the API contract writes "Z".
    """
    moment = moment or datetime.now(timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def connect(db_path="ledger.db"):
    """Open a ledger database and create its schema if needed."""
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def insert_event(conn, timestamp, session_id, action, resource, amount_cents, decision,
                  scope_id=None, request_id=None):
    """Append one event and return its database id.

    The caller owns the transaction. This is important for authorization:
    reading the aggregates and recording the decision must commit atomically.

    `amount_cents` is an integer number of cents; the schema rejects
    anything else. `scope_id` is the durable cross-session identity this
    event rolls up under (see aggregates.cumulative_cost_for_scope).
    Defaults to session_id, so a caller with no separate scope concept yet
    just scopes to itself - existing single-session behavior is unchanged.
    `request_id`, when given, is unique across the ledger (see
    find_by_request_id).
    """
    if scope_id is None:
        scope_id = session_id
    scope_id = normalize_scope(scope_id)
    cursor = conn.execute(
        "INSERT INTO events "
        "(timestamp, session_id, scope_id, home, action, resource, amount_cents, "
        "decision, request_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, session_id, scope_id, home_scope(scope_id), action, resource,
         amount_cents, decision, request_id),
    )
    return cursor.lastrowid


def find_by_request_id(conn, request_id):
    """The event already logged for this request_id, as
    (id, session_id, scope_id, resource, amount_cents, decision), or None."""
    return conn.execute(
        "SELECT id, session_id, scope_id, resource, amount_cents, decision "
        "FROM events WHERE request_id = ?",
        (request_id,),
    ).fetchone()


def list_events(conn, session_id=None, scope_id=None):
    """Return events in append order, optionally filtered by session and/or
    scope."""
    query = ("SELECT id, timestamp, session_id, scope_id, action, resource, "
             "amount_cents, decision FROM events")
    conditions = []
    params = []
    if session_id is not None:
        conditions.append("session_id = ?")
        params.append(session_id)
    if scope_id is not None:
        conditions.append("scope_id = ?")
        params.append(normalize_scope(scope_id))
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id"
    return conn.execute(query, params).fetchall()


def insert_override(conn, timestamp, scope_id, authorized_by, reason):
    """Record express human permission for a scope to resume after the
    circuit breaker trips it (see breaker.is_tripped). Append-only, same as
    events - this is the only way to un-trip a scope.

    The override covers every event already in the ledger and nothing
    after it. That cut-off is read from the ledger in the same statement,
    never from `timestamp`: a caller-supplied timestamp dated in the future
    would otherwise cover every DENY to come and switch the breaker off for
    good, and one written as "...Z" instead of "...+00:00" sorts after a
    DENY it actually came before.
    """
    cursor = conn.execute(
        "INSERT INTO overrides "
        "(timestamp, scope_id, authorized_by, reason, after_event_id) "
        "VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(id), 0) FROM events))",
        (timestamp, normalize_scope(scope_id), authorized_by, reason),
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
        (normalize_scope(scope_id),),
    ).fetchall()
