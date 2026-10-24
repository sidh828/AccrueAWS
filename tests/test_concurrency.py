"""Concurrency: many agents, sub-agents and retries hitting the guard at the
same instant, each on its own connection to one ledger file - the way the
API serves them. The guarantees (tests/guarantees.py) must still hold, and
no request may be lost, doubled or half-written."""

import random
import sqlite3
import threading

import pytest

from guard import authorize, ledger
from tests.guarantees import broken

pytestmark = pytest.mark.cedar

TOOL = {"gift_card": "buy_gift_card", "transfer": "send_zelle"}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "ledger.db")
    conn = ledger.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")  # as guard/api.py runs it
    # The grocer and the gift-card shop are long-standing payees.
    for payee, category in [("kroger.example", "groceries"), ("giftcards.example", "gift_card")]:
        ledger.insert_event(conn, "2026-01-01T00:00:00.000000Z", "h", "pay", payee, 100,
                            "ALLOW", scope_id="mom/bills-agent", payee=payee, category=category)
    conn.commit()
    conn.close()
    return path


def pay(path, amount, payee, category, chain=("mom", "bills-agent"), request_id=None,
        tainted=False):
    conn = ledger.connect(path)
    try:
        return authorize.authorize_payment(
            conn, person="mom", chain=list(chain), tool=TOOL.get(category, "pay_bill"),
            amount_cents=amount, payee=payee, category=category, session_id="s",
            request_id=request_id, tainted=tainted)
    finally:
        conn.close()


def at_once(calls):
    """Start every call together and wait for all of them."""
    gate, results = threading.Barrier(len(calls)), [None] * len(calls)

    def worker(i, call):
        gate.wait()
        try:
            results[i] = call()
        except sqlite3.OperationalError as err:
            # The write lock wasn't free in time: the API answers this as a
            # hold (fail closed). Kept as the error, so a test can check it
            # left nothing behind.
            results[i] = err

    threads = [threading.Thread(target=worker, args=(i, c)) for i, c in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def test_a_mixed_crowd_at_once_keeps_every_guarantee(db):
    """Sixty requests released together: sub-agents buying gift cards, a
    flood of new payees, transfers, groceries, some flagged as scams."""
    rng = random.Random(7)
    calls = []
    for i in range(60):
        kind = rng.choice(["gift", "new", "grocer", "transfer"])
        if kind == "gift":
            calls.append(lambda a=rng.choice([2_500, 5_000, 9_000]): pay(
                db, a, "giftcards.example", "gift_card",
                chain=("mom", "bills-agent", "giftcard-subagent")))
        elif kind == "new":
            calls.append(lambda i=i: pay(db, rng.choice([5_000, 19_000]), f"mule-{i}.example",
                                         "transfer"))
        elif kind == "grocer":
            calls.append(lambda: pay(db, 7_500, "kroger.example", "groceries"))
        else:
            calls.append(lambda i=i: pay(db, 45_000, f"zelle-{i}.example", "transfer",
                                         tainted=True))
    results = at_once(calls)

    answered = [r for r in results if isinstance(r, dict)]
    timed_out = [r for r in results if isinstance(r, sqlite3.OperationalError)]
    assert len(answered) + len(timed_out) == 60
    assert all(r["decision"] in ("allow", "deny", "hold") for r in answered)
    conn = ledger.connect(db)
    # Every answer is logged exactly once; a request that timed out on the
    # lock left nothing behind - it wasn't paid, and it isn't half-written.
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == len(answered) + 2
    assert broken(conn) == []


def test_retries_racing_each_other_are_one_payment(db):
    """An agent that times out and retries the same request ten times at
    once is paid once and logged once, and every copy gets the same
    answer."""
    results = at_once([lambda: pay(db, 12_000, "kroger.example", "groceries",
                                   request_id="retry-1")] * 10)
    assert len({r["event_id"] for r in results}) == 1
    assert {r["decision"] for r in results} == {"allow"}
    conn = ledger.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1 + 2
    assert broken(conn) == []


@pytest.mark.parametrize("round_", range(5))
def test_two_sub_agents_at_the_same_instant_cannot_both_fit(db, round_):
    """The plan's 'two sub-agents pay at the same instant; both see $400
    spent': $400 of the $500 is gone, and two sub-agents each ask for $100
    at once. Either alone fits; both together don't. Exactly one goes
    through, every round - the other waits for the family (Mom has paid
    the grocer before, so it's a hold, not a deny)."""
    for _ in range(4):
        pay(db, 10_000, "kroger.example", "groceries")
    results = at_once([
        lambda: pay(db, 10_000, "kroger.example", "groceries",
                    chain=("mom", "bills-agent", "sub-a")),
        lambda: pay(db, 10_000, "kroger.example", "groceries",
                    chain=("mom", "bills-agent", "sub-b")),
    ])
    assert sorted(r["decision"] for r in results) == ["allow", "hold"]
    assert broken(ledger.connect(db)) == []
