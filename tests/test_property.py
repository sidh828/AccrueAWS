"""Property tests: random households doing random things, through the real
guard and Cedar, and the guarantees in tests/guarantees.py checked after
every run.

Each run is a seeded random sequence: everyday payments, new payees, gift
cards, transfers, known bills that sometimes rise, amounts near every
limit, scam flags, the clock jumping minutes to days, and the family now
and then approving or denying what's held and resetting the breaker.

    ACCRUE_PROPERTY_RUNS=2000 pytest tests/test_property.py   # a longer soak

A failure names its seed: rerun with that seed to replay it exactly.
"""

import os
import random
from datetime import datetime, timedelta, timezone

import pytest

from guard import authorize, ledger
from tests.guarantees import broken

pytestmark = pytest.mark.cedar

RUNS = int(os.environ.get("ACCRUE_PROPERTY_RUNS", "40"))
STEPS = 40
START = datetime(2026, 9, 1, tzinfo=timezone.utc)
TOOL = {"gift_card": "buy_gift_card", "transfer": "send_zelle", "crypto": "send_crypto"}
# Near and around every limit, plus everyday amounts.
AMOUNTS = [1, 99, 100, 101, 1_000, 4_999, 5_000, 5_001, 9_999, 10_000, 10_001, 12_000,
           19_999, 20_000, 20_001, 24_999, 30_000, 45_000, 49_999, 50_000, 50_001, 120_000]


def household(conn, rng):
    """Two known bills and a few everyday payees, all paid well before the
    run starts."""
    payees = {"aep-ohio.example": "utility", "landlord.example": "rent",
              "kroger.example": "groceries", "cvs.example": "pharmacy",
              "giftcards.example": "gift_card"}
    for payee, category in payees.items():
        for months_ago in (2, 1):
            at = START - timedelta(days=30 * months_ago + rng.randrange(5))
            amount = {"utility": 11_000, "rent": 145_000}.get(category, rng.choice(AMOUNTS[3:9]))
            ledger.insert_event(conn, ledger.utc_timestamp(at), "history", "pay", payee, amount,
                                "ALLOW", scope_id="mom/bills-agent", payee=payee,
                                category=category)
    conn.commit()
    return payees


def run(seed):
    rng = random.Random(seed)
    conn = ledger.connect(":memory:")
    payees = household(conn, rng)
    now, held, strangers = START, [], 0
    for _ in range(STEPS):
        now += rng.choice([timedelta(seconds=30), timedelta(minutes=4), timedelta(hours=2),
                           timedelta(hours=13), timedelta(days=1), timedelta(days=9)])
        roll = rng.random()
        if roll < 0.08 and held:  # the family answers something waiting
            event_id = held.pop(rng.randrange(len(held)))
            authorize.resolve(conn, event_id, rng.choice(["approve", "deny"]), "daughter", now=now)
            continue
        if roll < 0.12:  # the family resets the breaker
            ledger.insert_override(conn, ledger.utc_timestamp(now), "mom", "daughter", "reset")
            conn.commit()
            continue
        if roll < 0.40:  # someone new - a contractor, a scammer, a mule
            strangers += 1
            payee = f"new-{strangers}.example"
            category = rng.choice(["transfer", "home_repair", "medical", "crypto"])
        else:
            payee = rng.choice(sorted(payees))
            category = payees[payee]
        amount = rng.choice(AMOUNTS)
        if category in ("utility", "rent") and rng.random() < 0.7:
            amount = {"utility": rng.choice([11_000, 13_200, 13_201, 9_000]),
                      "rent": rng.choice([145_000, 174_000, 174_001])}[category]
        response = authorize.authorize_payment(
            conn, person="mom", chain=["mom", "bills-agent"],
            tool=TOOL.get(category, "pay_bill"), amount_cents=amount, payee=payee,
            category=category, session_id="s", tainted=rng.random() < 0.2, now=now)
        if response["decision"] == "hold":
            held.append(response["event_id"])
    return conn


@pytest.mark.parametrize("seed", range(RUNS))
def test_random_households_never_break_a_guarantee(seed):
    conn = run(seed)
    assert broken(conn) == [], f"seed {seed}"


def test_the_checker_catches_a_breach():
    """The checker isn't vacuous: a payment slipped into the ledger past
    the guard - $600 in one go to someone new - is reported on every
    count it breaks."""
    conn = ledger.connect(":memory:")
    ledger.insert_event(
        conn, ledger.utc_timestamp(START), "s", "pay", "mule.example", 60_000, "ALLOW",
        scope_id="mom/bills-agent", payee="mule.example", category="transfer",
        context={"tainted": False, "known_bill": False, "last_bill": 0})
    conn.commit()
    problems = broken(conn)
    assert any("in 24 h" in p for p in problems)
    assert any("first payment to a new payee" in p for p in problems)
    assert any("recent payees" in p for p in problems)
