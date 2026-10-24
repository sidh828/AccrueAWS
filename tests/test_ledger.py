"""The append-only claim, actually enforced and actually tested.

See PRIMER.md 1.6: the whole trust story rests on "never update, never
delete." ledger.SCHEMA now has triggers that make that a database-level
guarantee instead of a convention nobody's checking; this file proves it.
"""

import sqlite3
import threading

import pytest

from src import authorize, ledger


@pytest.fixture
def conn():
    return ledger.connect(":memory:")


def test_update_is_rejected(conn):
    ledger.insert_event(conn, "t1", "sess-001", "transfer", "acct-1234", 100, "ALLOW")
    conn.commit()

    with pytest.raises(sqlite3.Error, match="append-only"):
        conn.execute("UPDATE events SET cost_usd = 0 WHERE id = 1")


def test_delete_is_rejected(conn):
    ledger.insert_event(conn, "t1", "sess-001", "transfer", "acct-1234", 100, "ALLOW")
    conn.commit()

    with pytest.raises(sqlite3.Error, match="append-only"):
        conn.execute("DELETE FROM events WHERE id = 1")


def test_concurrent_authorize_calls_serialize(tmp_path):
    """Proves the BEGIN IMMEDIATE claim in authorize.py's module docstring:
    two requests racing to spend from the same budget must not both read
    the same stale total and both get approved.

    Budget is 10000. Two concurrent $6000 transfers: individually each fits
    (6000 <= 10000), but together they'd total 12000 and blow the budget.
    If the check-then-log were not serialized, both could read
    already_spent=0 and both get ALLOW. BEGIN IMMEDIATE must force the
    second one to wait for the first's transaction to commit, then see the
    updated total and get DENY.
    """
    db_path = tmp_path / "ledger.db"
    # Pre-create the schema on one connection so both threads' connections
    # see the same tables.
    ledger.connect(str(db_path)).close()

    results = {}

    def attempt(name):
        conn = ledger.connect(str(db_path))
        results[name] = authorize.authorize_transfer(conn, "sess-001", "acct-1234", 6000)
        conn.close()

    t1 = threading.Thread(target=attempt, args=("a",))
    t2 = threading.Thread(target=attempt, args=("b",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    decisions = sorted(results.values())
    assert decisions == ["ALLOW", "DENY"], (
        f"expected exactly one ALLOW and one DENY out of two racing $6000 "
        f"transfers against a $10000 budget, got {results}"
    )
