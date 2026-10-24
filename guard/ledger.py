"""SQLite-backed append-only event log — the memory Cedar doesn't have.

See PRIMER.md Part 2. Rows are only ever inserted, never updated or deleted;
that's what makes the totals in aggregates.py trustworthy.

The triggers in SCHEMA refuse UPDATE and DELETE, but anyone with the file
can drop a trigger. So every row also carries row_hash, chained to the row
before it (see _chain_hash), and verify() walks the chain: editing,
inserting or deleting a row anywhere breaks it at that exact row.
"""

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone

from . import explain

# `home` is the first segment of scope_id (see home_scope), stored so the
# budget and breaker queries in aggregates.py are an indexed equality
# lookup instead of a scan of every row ever logged. (home, timestamp)
# serves the windowed total; (home) serves "last event" in id order.
#
# A row is never changed, including when the family settles a held payment:
# approving or denying it appends a new row whose `resolves` is the held
# row's id (see authorize.resolve). A held payment can be settled once,
# which the partial unique index enforces. Only ALLOW rows count toward
# any total, so a HOLD counts for nothing until a row approving it lands.
#
# payee, category, tool, chain, reason, rule and context are filled in by
# authorize.authorize_payment and empty on authorize_transfer's rows.
# `context` is the exact JSON Cedar was asked about: the record of why.
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
    decision    TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'HOLD')),
    request_id  TEXT UNIQUE,
    resolves    INTEGER REFERENCES events (id),
    payee       TEXT,
    category    TEXT,
    tool        TEXT,
    chain       TEXT,
    reason      TEXT,
    rule        TEXT,
    context     TEXT,
    row_hash    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id);
CREATE INDEX IF NOT EXISTS idx_events_scope_id ON events (scope_id);
CREATE INDEX IF NOT EXISTS idx_events_home ON events (home);
CREATE INDEX IF NOT EXISTS idx_events_home_time ON events (home, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_home_payee ON events (home, payee);
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_resolves ON events (resolves)
    WHERE resolves IS NOT NULL;

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
    after_event_id INTEGER NOT NULL,
    row_hash       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_overrides_scope_id ON overrides (scope_id);

-- The payout outbox. The guard is the only thing that can pay (CLAUDE.md),
-- so every payment that goes through - allowed outright, or held and then
-- approved by the family - queues exactly one payout here, in the same
-- transaction as the decision. Whatever sends money takes from this queue
-- and marks each one sent; it never acts on an /authorize answer, which a
-- retried request_id returns again. UNIQUE(event_id) is the "at most once".
CREATE TABLE IF NOT EXISTS payouts (
    id           INTEGER PRIMARY KEY,
    event_id     INTEGER NOT NULL UNIQUE REFERENCES events (id),
    queued_at    TEXT NOT NULL,
    payee        TEXT NOT NULL,
    amount_cents INTEGER NOT NULL CHECK (typeof(amount_cents) = 'integer' AND amount_cents > 0),
    sent_at      TEXT
);

-- Untrusted text that reached the agent (POST /inbound from an untrusted
-- source). The guard serves one household, so any of it makes the whole
-- household's next hours stricter - not just the session that saw it,
-- because a new conversation is a new session (see api.answer_authorize).
CREATE TABLE IF NOT EXISTS untrusted_inbound (
    id         INTEGER PRIMARY KEY,
    at         TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source     TEXT NOT NULL
);

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


# How long a connection waits for another's write lock before giving up
# with "database is locked". Each decision holds the lock for milliseconds
# (Cedar's own timeout caps it at 2 s), so a burst of requests queues up
# behind each other; SQLite's default of 5 s was too short for 60 at once on
# a slow CI runner. Giving up is still safe - the API answers it as a hold.
BUSY_TIMEOUT_SECONDS = 15


def connect(db_path="ledger.db"):
    """Open a ledger database and create its schema if needed."""
    conn = sqlite3.connect(db_path, timeout=BUSY_TIMEOUT_SECONDS)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


# --- Hash chain -----------------------------------------------------------
#
# row_hash = sha256(previous row's row_hash + canonical JSON of this row),
# starting from GENESIS_HASH, with the row's id and every column but
# row_hash itself, exactly as stored. events and overrides are separate
# chains. Changing any stored value, or removing or slipping in a row,
# makes that row's hash disagree with the one recomputed from the row
# before it.
#
# Plain sha256 catches edits, not someone with the file who edits a row and
# then recomputes every hash after it. Two things stop that: head() is
# meant to be shown off the box (dashboard, phone alert) and checked with
# verify(anchor=...), and with ACCRUE_LEDGER_KEY set the hash is an HMAC
# under a key that lives with the guard process, not in the file.

GENESIS_HASH = "0" * 64

# What each chain hashes, besides the id. Order doesn't matter (the JSON is
# key-sorted), but every stored column must be here.
_EVENT_HASHED = ("timestamp", "session_id", "scope_id", "home", "action",
                 "resource", "amount_cents", "decision", "request_id", "resolves",
                 "payee", "category", "tool", "chain", "reason", "rule", "context")
_OVERRIDE_HASHED = ("timestamp", "scope_id", "authorized_by", "reason",
                    "after_event_id")


def _chain_hash(prev_hash, row):
    payload = prev_hash + json.dumps(row, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False)
    key = os.environ.get("ACCRUE_LEDGER_KEY")
    if key:
        return hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(payload.encode()).hexdigest()


def _append(conn, table, row):
    """Insert `row` (column -> value) into `table` as the next link of its
    chain and return its id. The id is assigned here, not by SQLite, so it
    can be part of what's hashed. The caller owns the transaction."""
    next_id, prev_hash = conn.execute(
        f"SELECT COALESCE(MAX(id), 0) + 1, "
        f"(SELECT row_hash FROM {table} ORDER BY id DESC LIMIT 1) FROM {table}"
    ).fetchone()
    row = {"id": next_id, **row}
    row["row_hash"] = _chain_hash(prev_hash or GENESIS_HASH,
                                  {k: v for k, v in row.items() if k != "row_hash"})
    columns = ", ".join(row)
    conn.execute(f"INSERT INTO {table} ({columns}) VALUES ({', '.join('?' * len(row))})",
                 tuple(row.values()))
    return next_id


def queue_payout(conn, event_id, at, payee, amount_cents):
    """Queue the one payout for payment `event_id`. The caller owns the
    transaction - it's the same one that records the decision. Queueing
    the same event twice is a no-op: that's what makes paying at most once
    something the database guarantees."""
    conn.execute(
        "INSERT OR IGNORE INTO payouts (event_id, queued_at, payee, amount_cents) "
        "VALUES (?, ?, ?, ?)",
        (event_id, at, payee, amount_cents),
    )


def queued_payouts(conn):
    """Payouts not yet sent, oldest first, as dicts."""
    rows = conn.execute(
        "SELECT id, event_id, queued_at, payee, amount_cents FROM payouts "
        "WHERE sent_at IS NULL ORDER BY id"
    ).fetchall()
    return [dict(zip(("payout_id", "event_id", "queued_at", "payee", "amount_cents"), r))
            for r in rows]


def mark_sent(conn, payout_id, at):
    """Record that a payout went out. True the first time; False if it had
    already been marked, so a sender that crashed and retries can tell it
    must not send again. Commits."""
    sent = conn.execute("UPDATE payouts SET sent_at = ? WHERE id = ? AND sent_at IS NULL",
                        (at, payout_id)).rowcount == 1
    conn.commit()
    return sent


def record_untrusted(conn, at, session_id, source):
    """Note that untrusted text reached the agent at `at` (a ledger
    timestamp). Commits."""
    conn.execute("INSERT INTO untrusted_inbound (at, session_id, source) VALUES (?, ?, ?)",
                 (at, session_id, source))
    conn.commit()


def untrusted_since(conn, since):
    """Whether any untrusted text reached the agent at or after `since`."""
    return conn.execute("SELECT 1 FROM untrusted_inbound WHERE at >= ? LIMIT 1",
                        (since,)).fetchone() is not None


def head(conn):
    """The last event's id and row_hash, or None for an empty ledger. Shown
    somewhere the ledger file can't reach, it lets verify() catch a rewrite
    of everything up to it."""
    row = conn.execute("SELECT id, row_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    return None if row is None else {"event_id": row[0], "row_hash": row[1]}


def verify(conn, anchor=None):
    """Walk both chains in id order. Returns {"ok", "first_bad_event_id",
    "first_bad_override_id", "head"}: the first row whose hash doesn't
    match what the row before it says it should be, in each chain, or None.

    `anchor` is a head() taken earlier and kept off the box. If the row it
    names is gone or has a different hash now, that row is reported - even
    if everything up to it was rewritten and re-hashed consistently.
    """
    found = {}
    for table, columns, key in (("events", _EVENT_HASHED, "first_bad_event_id"),
                                ("overrides", _OVERRIDE_HASHED, "first_bad_override_id")):
        found[key] = None
        prev_hash = GENESIS_HASH
        rows = conn.execute(
            f"SELECT id, row_hash, {', '.join(columns)} FROM {table} ORDER BY id"
        )
        for row_id, stored, *values in rows:
            if stored != _chain_hash(prev_hash, {"id": row_id, **dict(zip(columns, values))}):
                found[key] = row_id
                break
            prev_hash = stored

    if anchor is not None:
        row = conn.execute("SELECT row_hash FROM events WHERE id = ?",
                           (anchor["event_id"],)).fetchone()
        if row is None or row[0] != anchor["row_hash"]:
            bad = found["first_bad_event_id"]
            found["first_bad_event_id"] = (anchor["event_id"] if bad is None
                                           else min(bad, anchor["event_id"]))

    return {"ok": all(v is None for v in found.values()), **found, "head": head(conn)}


def insert_event(conn, timestamp, session_id, action, resource, amount_cents, decision,
                  scope_id=None, request_id=None, resolves=None, payee=None,
                  category=None, tool=None, chain=None, reason=None, rule=None,
                  context=None):
    """Append one event and return its database id.

    The caller owns the transaction. This is important for authorization:
    reading the aggregates and recording the decision must commit atomically.

    `amount_cents` is an integer number of cents; the schema rejects
    anything else. `scope_id` is the durable cross-session identity this
    event rolls up under (see aggregates.cumulative_cost_for_scope).
    Defaults to session_id, so a caller with no separate scope concept yet
    just scopes to itself - existing single-session behavior is unchanged.
    `request_id`, when given, is unique across the ledger (see
    find_by_request_id). The rest describe a family payment (see SCHEMA);
    `chain` is a list and `context` a dict, both stored as JSON.
    """
    if scope_id is None:
        scope_id = session_id
    scope_id = normalize_scope(scope_id)
    return _append(conn, "events", {
        "timestamp": timestamp,
        "session_id": session_id,
        "scope_id": scope_id,
        "home": home_scope(scope_id),
        "action": action,
        "resource": resource,
        "amount_cents": amount_cents,
        "decision": decision,
        "request_id": request_id,
        "resolves": resolves,
        "payee": payee,
        "category": category,
        "tool": tool,
        "chain": None if chain is None else json.dumps(chain),
        "reason": reason,
        "rule": rule,
        "context": None if context is None else json.dumps(context, sort_keys=True),
    })


# Columns read back by get_event and contract_rows, in this order.
_ROW_COLUMNS = ("id", "timestamp", "session_id", "scope_id", "home", "action",
                "resource", "amount_cents", "decision", "request_id", "resolves",
                "payee", "category", "tool", "chain", "reason", "rule", "context",
                "row_hash")


def _row_dict(row):
    event = dict(zip(_ROW_COLUMNS, row))
    event["chain"] = json.loads(event["chain"]) if event["chain"] else None
    event["context"] = json.loads(event["context"]) if event["context"] else None
    return event


def get_event(conn, event_id):
    """One event as a dict of its columns (chain and context decoded), or
    None."""
    row = conn.execute(
        f"SELECT {', '.join(_ROW_COLUMNS)} FROM events WHERE id = ?", (event_id,)
    ).fetchone()
    return None if row is None else _row_dict(row)


# CLAUDE.md's event row: decision is lowercase, status follows from it.
_STATUS = {"ALLOW": "allowed", "DENY": "released", "HOLD": "held"}


def _contract_shape(event):
    decision = event["decision"]
    context = event["context"] or {}
    notice = None
    if decision == "ALLOW" and context.get("new_payee"):
        notice = "new_payee"
    elif decision == "ALLOW" and context.get("recent_payee"):
        notice = "recent_payee"
    return {
        "event_id": event["id"],
        "ts": event["timestamp"],
        "status": _STATUS[decision],
        "person": event["home"],
        "chain": event["chain"] or event["scope_id"].split("/"),
        "tool": event["tool"] or event["action"],
        "amount_cents": event["amount_cents"],
        "payee": event["payee"] or event["resource"],
        "category": event["category"],
        "decision": decision.lower(),
        "rule": event["rule"],
        "explanation": explain.explain(event),
        "flagged": decision != "ALLOW",
        "row_hash": event["row_hash"],
        "resolves": event["resolves"],
        "notice": notice,
        "known_bill": bool(context.get("known_bill")),
    }


def contract_rows(conn, since=0):
    """Events with an id above `since`, in id order, shaped as CLAUDE.md's
    event row: the ledger as it is, one row per entry.

    Three fields are added to the contract's:

    - `resolves`: the event_id of the held payment this row approves or
      denies (None otherwise). A held row is settled once a later row
      resolves it; the held row itself never changes. (api.py folds each
      resolving row into the payment it settles before sending rows to the
      dashboard; see api.payment_views.)
    - `notice`: "new_payee" (a first payment ever) or "recent_payee" (to
      someone first paid in the last 30 days) on a payment that went
      through, else None. It's the FYI alert for payments no rule stopped:
      a patient scam never trips a rule, so this is how the family hears
      about it.
    - `known_bill`: the guard recognized this as a known bill (rent or a
      utility within its usual amount), which the day's total leaves out.

    `explanation` is guard.explain's plain-English sentence for the
    decision, worked out from the logged context when the row is read.
    """
    rows = conn.execute(
        f"SELECT {', '.join(_ROW_COLUMNS)} FROM events WHERE id > ? ORDER BY id",
        (since,),
    ).fetchall()
    return [_contract_shape(_row_dict(row)) for row in rows]


def contract_row(conn, event_id):
    """One event shaped as contract_rows shapes it, or None."""
    event = get_event(conn, event_id)
    return None if event is None else _contract_shape(event)


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
    after it. That cut-off is read from the ledger, never from
    `timestamp`: a caller-supplied timestamp dated in the future would
    otherwise cover every DENY to come and switch the breaker off for
    good, and one written as "...Z" instead of "...+00:00" sorts after a
    DENY it actually came before. Like events, overrides are hash-chained.
    """
    (after_event_id,) = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()
    return _append(conn, "overrides", {
        "timestamp": timestamp,
        "scope_id": normalize_scope(scope_id),
        "authorized_by": authorized_by,
        "reason": reason,
        "after_event_id": after_event_id,
    })


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
