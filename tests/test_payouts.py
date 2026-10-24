"""The payout outbox: the guard is the only thing that can pay, and each
payment that goes through is paid exactly once - however many times the
agent retries, races itself, or the family is asked."""

import threading

import pytest

from guard import authorize, ledger
from tests.guarantees import broken

pytestmark = pytest.mark.cedar


def pay(conn, amount=5_000, payee="kroger.example", request_id=None, tainted=False,
        category="groceries"):
    return authorize.authorize_payment(
        conn, person="mom", chain=["mom", "bills-agent"],
        tool={"gift_card": "buy_gift_card", "transfer": "send_zelle"}.get(category, "pay_bill"),
        amount_cents=amount, payee=payee, category=category, session_id="s",
        request_id=request_id, tainted=tainted)


@pytest.fixture
def conn():
    c = ledger.connect(":memory:")
    ledger.insert_event(c, "2026-01-01T00:00:00.000000Z", "h", "pay", "kroger.example", 100,
                        "ALLOW", scope_id="mom/bills-agent", payee="kroger.example",
                        category="groceries")
    c.commit()
    return c


def test_an_allowed_payment_queues_one_payout(conn):
    response = pay(conn)
    assert ledger.queued_payouts(conn) == [{
        "payout_id": 1, "event_id": response["event_id"],
        "queued_at": ledger.get_event(conn, response["event_id"])["timestamp"],
        "payee": "kroger.example", "amount_cents": 5_000}]
    assert broken(conn) == []


def test_a_retry_is_never_paid_twice(conn):
    """The agent times out and asks again with the same request_id: the
    same allow comes back, and there's still one payout."""
    first = pay(conn, request_id="r1")
    again = pay(conn, request_id="r1")
    assert first == again
    assert len(ledger.queued_payouts(conn)) == 1


def test_racing_retries_are_paid_once(tmp_path):
    path = str(tmp_path / "ledger.db")
    c = ledger.connect(path)
    ledger.insert_event(c, "2026-01-01T00:00:00.000000Z", "h", "pay", "kroger.example", 100,
                        "ALLOW", scope_id="mom/bills-agent", payee="kroger.example",
                        category="groceries")
    c.commit()

    def attempt():
        conn = ledger.connect(path)
        try:
            pay(conn, request_id="same-request")
        finally:
            conn.close()

    threads = [threading.Thread(target=attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ledger.queued_payouts(ledger.connect(path))) == 1


def test_stopped_and_held_payments_queue_nothing(conn):
    pay(conn, 60_000)  # over the day: held for the family
    pay(conn, 30_000, "zelle:new-contact", category="transfer")  # new payee over $200: stopped
    assert ledger.queued_payouts(conn) == []


def test_an_approved_hold_is_paid_once_and_a_denied_one_never(conn):
    held = pay(conn, 5_000, "giftcards.example", tainted=True, category="gift_card")
    denied = pay(conn, 2_500, "giftcards.example", tainted=True, category="gift_card")
    authorize.resolve(conn, held["event_id"], "approve", "daughter")
    authorize.resolve(conn, denied["event_id"], "deny", "daughter")
    [payout] = ledger.queued_payouts(conn)
    assert (payout["event_id"], payout["amount_cents"]) == (held["event_id"], 5_000)
    assert broken(conn) == []


def test_a_sender_that_crashes_and_retries_cannot_send_twice(conn):
    pay(conn)
    [payout] = ledger.queued_payouts(conn)
    assert ledger.mark_sent(conn, payout["payout_id"], ledger.utc_timestamp()) is True
    assert ledger.mark_sent(conn, payout["payout_id"], ledger.utc_timestamp()) is False
    assert ledger.queued_payouts(conn) == []


def test_the_checker_catches_a_missing_or_extra_payout(conn):
    response = pay(conn)
    conn.execute("DELETE FROM payouts")
    conn.commit()
    assert any("payouts" in p for p in broken(conn))
    ledger.queue_payout(conn, response["event_id"], "t", "kroger.example", 5_000)
    ledger.queue_payout(conn, 1, "t", "kroger.example", 100)  # history, never paid by the guard
    conn.commit()
    assert any("payouts" in p for p in broken(conn))
