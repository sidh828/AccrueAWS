"""The headline, under load: many $1 payments released at the same instant
land exactly on the $500 daily cap - not a cent over, not a cent under -
and everything past it waits for the family.

    ACCRUE_STORM=600 pytest tests/test_cap_storm.py   # EVIDENCE.md's run
"""

import os
import sqlite3

import pytest

from guard import authorize, ledger
from tests.guarantees import broken
from tests.test_concurrency import at_once, db, pay  # noqa: F401 (db is a fixture)

pytestmark = pytest.mark.cedar

STORM = int(os.environ.get("ACCRUE_STORM", "120"))


def test_a_storm_of_requests_lands_exactly_on_the_cap(db):  # noqa: F811
    cap = authorize.FAMILY_LIMITS["day"]
    fits = cap // 100
    count = max(STORM, fits + 20)
    results = at_once([lambda i=i: pay(db, 100, "kroger.example", "groceries",
                                       request_id=f"storm-{i}") for i in range(count)])

    answered = [r for r in results if isinstance(r, dict)]
    # A request that can't get the lock in time gets this error, which the
    # API answers as a hold (fail closed). The writer queue in authorize.py
    # serves a storm this size well inside that time, so none should.
    timed_out = [r for r in results if isinstance(r, sqlite3.OperationalError)]
    allowed = [r for r in answered if r["decision"] == "allow"]
    assert len(answered) + len(timed_out) == count
    assert not timed_out, f"{len(timed_out)} of {count} timed out on the lock"
    assert {r["decision"] for r in answered if r["decision"] != "allow"} == {"hold"}
    conn = ledger.connect(db)
    spent = conn.execute("SELECT SUM(amount_cents) FROM events "
                         "WHERE decision = 'ALLOW' AND request_id LIKE 'storm-%'").fetchone()[0]
    assert spent == 100 * len(allowed) == cap
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == count + 2
    print(f"\n{count} at once: {len(allowed)} allowed (${spent // 100}), "
          f"{len(answered) - len(allowed)} held, {len(timed_out)} timed out on the lock (held)")
    assert broken(conn) == []
