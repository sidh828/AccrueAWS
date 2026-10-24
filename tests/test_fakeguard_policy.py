"""Policy-parity checks for the in-memory guard simulation against real Cedar."""
from datetime import datetime, timedelta, timezone
import time

import pytest

from agent.scenarios.common import FakeClock
from agent.tools import FakeGuard, ToolBox
from guard import authorize, ledger

pytestmark = pytest.mark.cedar
CHAIN = ["mom", "bills-agent"]


def seed(conn, payee, amount_cents, category, at):
    ledger.insert_event(
        conn,
        ledger.utc_timestamp(at),
        "history",
        "pay",
        payee,
        amount_cents,
        "ALLOW",
        scope_id="mom/bills-agent",
        payee=payee,
        category=category,
        tool="pay_bill",
        chain=CHAIN,
    )


def actual(conn, payee, amount_cents, category, tainted=False):
    tool = {
        "gift_card": "buy_gift_card",
        "transfer": "send_zelle",
    }.get(category, "pay_bill")
    return authorize.authorize_payment(
        conn,
        person="mom",
        chain=CHAIN,
        tool=tool,
        amount_cents=amount_cents,
        payee=payee,
        category=category,
        session_id="session",
        tainted=tainted,
    )


def simulated(tools, payee, amount_cents, category, tainted=False):
    if tainted:
        tools.receive_message("sms", "untrusted message")
    if category == "gift_card":
        return tools.buy_gift_card(payee, amount_cents)
    if category == "transfer":
        return tools.send_zelle(payee, amount_cents)
    return tools.pay_bill(payee, amount_cents, category=category)


def assert_same_outcome(real, fake):
    real_rule = "ok" if real["decision"] == "allow" and real["rule"] is None else real["rule"]
    assert (real["decision"], real_rule) == (fake["decision"], fake["rule"])


def test_fake_matches_cedar_for_known_bill_exemption_and_increase_cap():
    now = datetime.now(timezone.utc)
    conn = ledger.connect(":memory:")
    seed(conn, "power.example", 10_000, "utility", now - timedelta(days=30))
    seed(conn, "grocer.example", 49_000, "groceries", now - timedelta(minutes=1))
    conn.commit()

    fake = FakeGuard(
        clock=FakeClock(time.time()),
        known_payees={"grocer.example"},
        known_bills={"power.example": 10_000},
    )
    tools = ToolBox(fake, session_id="session")
    simulated(tools, "grocer.example", 49_000, "groceries")
    assert_same_outcome(
        actual(conn, "power.example", 12_000, "utility"),
        simulated(tools, "power.example", 12_000, "utility"),
    )
    assert_same_outcome(
        actual(conn, "power.example", 14_401, "utility"),
        simulated(tools, "power.example", 14_401, "utility"),
    )
    conn.close()


def test_fake_matches_cedar_for_tainted_gift_card_approval():
    conn = ledger.connect(":memory:")
    fake = FakeGuard(clock=FakeClock(time.time()))
    tools = ToolBox(fake, session_id="session")

    real_result = actual(conn, "giftcards.example", 5_000, "gift_card", tainted=True)
    fake_result = simulated(tools, "giftcards.example", 5_000, "gift_card", tainted=True)

    assert_same_outcome(real_result, fake_result)
    assert real_result["decision"] == "hold"
    conn.close()


def test_fake_matches_cedar_for_breaker_and_deny_precedence():
    conn = ledger.connect(":memory:")
    fake = FakeGuard(clock=FakeClock(time.time()))
    tools = ToolBox(fake, session_id="session")

    for index in range(3):
        payee = f"new-{index}.example"
        assert_same_outcome(
            actual(conn, payee, 30_000, "transfer"),
            tools.send_zelle(payee, 30_000),
        )

    assert_same_outcome(
        actual(conn, "power-company.example", 1_000, "bill"),
        tools.pay_bill("power-company.example", 1_000),
    )
    conn.close()
