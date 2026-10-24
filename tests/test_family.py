"""The family's spending rules (CLAUDE.md, "Spending rules") through
authorize.authorize_payment and the real family.cedar, plus holding a
payment for the family and settling it with authorize.resolve.

Amounts are integer cents: 50_000 is $500. The rule-to-outcome choices are
the ones posted on issue #1.
"""

import re
import subprocess
import threading
from datetime import datetime, timedelta, timezone

import pytest

from guard import authorize, ledger

# Every test here runs the cedar CLI: skipped without it (tests/conftest.py).
pytestmark = pytest.mark.cedar

BILLS = ["mom", "bills-agent"]


@pytest.fixture
def conn():
    return ledger.connect(":memory:")


def pay(conn, amount, payee="grocer.example", category="groceries", tainted=False,
        chain=BILLS, **kwargs):
    return authorize.authorize_payment(
        conn, person="mom", chain=list(chain), tool="pay_bill", amount_cents=amount,
        payee=payee, category=category, session_id="sess-1", tainted=tainted, **kwargs,
    )


def paid_before(conn, payee, amount=100, category="groceries", days_ago=2):
    """Log an allowed payment from before today's window, so `payee` isn't
    new and today's totals start at zero."""
    when = datetime.now(timezone.utc) - timedelta(days=days_ago)
    ledger.insert_event(
        conn, ledger.utc_timestamp(when), "sess-0", "pay", payee, amount, "ALLOW",
        scope_id="mom/bills-agent", payee=payee, category=category,
    )
    conn.commit()


def outcome(response):
    return response["decision"], response["rule"]


# --- The policy itself -----------------------------------------------------

def test_family_policy_validates_against_its_schema():
    result = subprocess.run(
        ["cedar", "validate", "--schema", str(authorize.FAMILY_SCHEMA_PATH),
         "--policies", str(authorize.FAMILY_POLICY_PATH)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_rule_in_the_policy_has_an_outcome():
    """A forbid the guard doesn't know would be treated as a deny; this
    keeps family.cedar and RULE_OUTCOMES in step so none is a surprise."""
    ids = set(re.findall(r'@id\("([^"]+)"\)', authorize.FAMILY_POLICY_PATH.read_text()))
    assert ids - {"allow_by_default"} == set(authorize.RULE_OUTCOMES)


# --- One test per rule ----------------------------------------------------------

def test_daily_cap_is_500(conn):
    paid_before(conn, "grocer.example")
    assert outcome(pay(conn, 30_000)) == ("allow", None)
    response = pay(conn, 20_000)
    assert outcome(response) == ("allow", None)
    assert response["totals"]["day"] == 50_000 and response["limits"]["day"] == 50_000

    response = pay(conn, 1)
    assert outcome(response) == ("deny", "daily_cap")
    assert response["totals"]["day"] == 50_001 and response["needs_approval"] is False


def test_daily_cap_is_100_after_a_scam_flag(conn):
    paid_before(conn, "grocer.example")
    assert outcome(pay(conn, 10_000, tainted=True)) == ("allow", None)
    response = pay(conn, 1, tainted=True)
    assert outcome(response) == ("deny", "daily_cap")
    assert response["limits"]["day"] == 10_000


def test_gift_cards_are_capped_at_100_a_day(conn):
    """The demo's first beat: a $50 birthday gift card goes through, then a
    $450 one is stopped."""
    paid_before(conn, "giftcards.example", category="gift_card")
    assert outcome(pay(conn, 5_000, "giftcards.example", "gift_card")) == ("allow", None)
    response = pay(conn, 45_000, "giftcards.example", "gift_card")
    assert outcome(response) == ("deny", "gift_card_daily_cap")
    assert response["totals"]["gift_card_day"] == 50_000


def test_every_gift_card_waits_after_a_scam_flag(conn):
    paid_before(conn, "giftcards.example", category="gift_card")
    response = pay(conn, 5_000, "giftcards.example", "gift_card", tainted=True)
    assert outcome(response) == ("hold", "gift_card_needs_approval")
    assert response["needs_approval"] is True


def test_first_payment_to_someone_new_is_capped_at_200(conn):
    assert outcome(pay(conn, 20_000, "plumber.example", "home_repair")) == ("allow", None)
    assert outcome(pay(conn, 20_001, "zelle:new-contact", "transfer")) == (
        "deny", "new_payee_cap")
    # Paid once, the plumber isn't new any more.
    assert outcome(pay(conn, 20_001, "plumber.example", "home_repair")) == ("allow", None)


def test_any_first_payment_waits_after_a_scam_flag(conn):
    assert outcome(pay(conn, 100, "zelle:new-contact", "transfer", tainted=True)) == (
        "hold", "new_payee_needs_approval")


def test_known_bills_can_rise_20_percent_and_are_exempt_from_the_daily_cap(conn):
    paid_before(conn, "ohio-power.example", 10_000, "utility", days_ago=30)
    assert outcome(pay(conn, 12_000, "ohio-power.example", "utility")) == ("allow", None)
    # Last time was $120 now, so $144 is the most it can be without asking.
    assert outcome(pay(conn, 14_401, "ohio-power.example", "utility")) == (
        "hold", "bill_increase")
    assert outcome(pay(conn, 14_400, "ohio-power.example", "utility")) == ("allow", None)

    paid_before(conn, "landlord.example", 120_000, "rent", days_ago=31)
    assert outcome(pay(conn, 120_000, "landlord.example", "rent")) == ("allow", None)
    # The rent is over $500 on its own and went through, but it still counts:
    # the day's total is spent.
    paid_before(conn, "grocer.example")
    assert outcome(pay(conn, 100)) == ("deny", "daily_cap")


def test_three_denials_in_ten_minutes_hold_everything(conn):
    paid_before(conn, "grocer.example")
    for i in range(3):
        assert outcome(pay(conn, 30_000, f"stranger-{i}.example", "transfer")) == (
            "deny", "new_payee_cap")

    # A payment that's fine on its own now waits for the family.
    assert outcome(pay(conn, 1_000)) == ("hold", "breaker")

    # The family resetting the breaker lets the next one through.
    ledger.insert_override(conn, ledger.utc_timestamp(), "mom", "daughter", "checked")
    conn.commit()
    assert outcome(pay(conn, 1_000)) == ("allow", None)


def test_one_denial_holds_everything_after_a_scam_flag(conn):
    paid_before(conn, "grocer.example")
    assert outcome(pay(conn, 30_000, "stranger.example", "transfer")) == (
        "deny", "new_payee_cap")
    assert outcome(pay(conn, 1_000, tainted=True)) == ("hold", "breaker")


def test_a_deny_beats_a_hold(conn):
    paid_before(conn, "grocer.example")
    pay(conn, 50_000)
    # Over the daily cap (deny) and a tainted gift card (hold): deny wins.
    response = pay(conn, 5_000, "giftcards.example", "gift_card", tainted=True)
    assert outcome(response) == ("deny", "daily_cap")


def test_the_most_specific_rule_is_reported(conn):
    """The scam day: after $170 of ordinary spending, a $450 gift card is
    over both the gift card cap and the daily cap. The dashboard says
    "gift card blocked", so the gift card rule is the one reported; the
    same for a $450 Zelle to someone new."""
    paid_before(conn, "ohio-power.example", 11_000, "utility", days_ago=30)
    paid_before(conn, "giftcards.example", category="gift_card")
    pay(conn, 12_000, "ohio-power.example", "utility")
    pay(conn, 5_000, "giftcards.example", "gift_card")
    assert outcome(pay(conn, 45_000, "giftcards.example", "gift_card")) == (
        "deny", "gift_card_daily_cap")
    assert outcome(pay(conn, 45_000, "zelle:new-contact", "transfer")) == (
        "deny", "new_payee_cap")


# --- Holds and the family's answer ---------------------------------------------

def test_a_held_payment_counts_only_once_approved(conn):
    paid_before(conn, "grocer.example")
    held = pay(conn, 5_000, "giftcards.example", "gift_card", tainted=True)
    assert held["decision"] == "hold"

    # Not counted while it waits: the full $500 is still there.
    assert outcome(pay(conn, 50_000)) == ("allow", None)

    approval = authorize.resolve(conn, held["event_id"], "approve", "daughter")
    rows = ledger.contract_rows(conn)
    assert rows[-1]["event_id"] == approval and rows[-1]["resolves"] == held["event_id"]
    assert rows[-1]["status"] == "allowed"

    # Counted from the approval on - and it went through past the limit,
    # because the family is the override.
    response = pay(conn, 1)
    assert outcome(response) == ("deny", "daily_cap")
    assert response["totals"]["day"] == 55_001


def test_a_denied_hold_never_counts(conn):
    paid_before(conn, "grocer.example")
    held = pay(conn, 5_000, "zelle:new-contact", "transfer", tainted=True)
    assert held["decision"] == "hold"
    authorize.resolve(conn, held["event_id"], "deny", "daughter")
    assert ledger.contract_rows(conn)[-1]["status"] == "released"
    assert outcome(pay(conn, 50_000)) == ("allow", None)


def test_only_a_hold_can_be_resolved_and_only_once(conn):
    paid_before(conn, "grocer.example")
    allowed = pay(conn, 1_000)
    with pytest.raises(ValueError, match="not a payment waiting"):
        authorize.resolve(conn, allowed["event_id"], "approve", "daughter")

    held = pay(conn, 100, "zelle:new-contact", "transfer", tainted=True)
    authorize.resolve(conn, held["event_id"], "deny", "daughter")
    with pytest.raises(ValueError, match="already resolved"):
        authorize.resolve(conn, held["event_id"], "approve", "daughter")
    with pytest.raises(ValueError, match="action"):
        authorize.resolve(conn, held["event_id"], "maybe", "daughter")


# --- Failing closed, retries, malformed input ------------------------------------

def test_a_broken_rules_engine_holds_the_payment(conn, monkeypatch, tmp_path):
    """Fail closed: Cedar missing (or crashing, or timing out) logs a hold,
    never an allow."""
    monkeypatch.setattr(authorize, "CEDAR_BIN", str(tmp_path / "no-such-cedar"))
    response = pay(conn, 1_000)
    assert outcome(response) == ("hold", "guard_unavailable")
    assert ledger.get_event(conn, response["event_id"])["decision"] == "HOLD"


def test_a_retried_request_gets_the_same_answer(conn):
    paid_before(conn, "grocer.example")
    first = pay(conn, 40_000, request_id="req-1")
    assert pay(conn, 40_000, request_id="req-1") == first
    assert outcome(pay(conn, 10_000, request_id="req-2")) == ("allow", None)


@pytest.mark.parametrize("chain", [["dad", "bills-agent"], ["mom/x", "bills-agent"], []])
def test_the_chain_must_start_with_the_person_paying(conn, chain):
    with pytest.raises(ValueError, match="chain"):
        pay(conn, 1_000, chain=chain)
    assert ledger.contract_rows(conn) == []


def test_names_are_case_insensitive(conn):
    """"Mom" and "mom", "GiftCards.example" and "giftcards.example" are the
    same person and payee."""
    paid_before(conn, "giftcards.example", category="gift_card")
    assert outcome(pay(conn, 5_000, "GiftCards.Example", "Gift_Card",
                       chain=["Mom", "Bills-Agent"])) == ("allow", None)
    assert outcome(pay(conn, 5_001, "giftcards.example", "gift_card")) == (
        "deny", "gift_card_daily_cap")


# --- What the dashboard reads ---------------------------------------------------

def test_event_rows_have_the_contract_fields(conn):
    contract = {"event_id", "ts", "status", "person", "chain", "tool", "amount_cents",
                "payee", "category", "decision", "rule", "explanation", "flagged",
                "row_hash"}
    paid_before(conn, "giftcards.example", category="gift_card")
    pay(conn, 5_000, "giftcards.example", "gift_card",
        chain=["mom", "bills-agent", "giftcard-subagent"])
    pay(conn, 45_000, "giftcards.example", "gift_card")
    held = pay(conn, 100, "zelle:new-contact", "transfer", tainted=True)
    authorize.resolve(conn, held["event_id"], "approve", "daughter")

    rows = ledger.contract_rows(conn)
    assert all(set(r) == contract | {"resolves"} for r in rows)
    assert [(r["decision"], r["status"]) for r in rows[1:]] == [
        ("allow", "allowed"), ("deny", "released"), ("hold", "held"), ("allow", "allowed")]
    assert rows[1]["chain"] == ["mom", "bills-agent", "giftcard-subagent"]
    assert rows[1]["person"] == "mom" and rows[1]["ts"].endswith("Z")
    assert ledger.contract_rows(conn, since=rows[-2]["event_id"]) == rows[-1:]


def test_fifty_payments_at_once_land_exactly_on_the_cap(tmp_path):
    """The proof-panel demo: fifty $50 payments fired at once. Exactly ten
    are allowed - $500, to the cent - and the rest are denied, or held once
    the breaker trips."""
    db_path = str(tmp_path / "ledger.db")
    paid_before(ledger.connect(db_path), "grocer.example")
    results = []

    def attempt():
        conn = ledger.connect(db_path)
        results.append(pay(conn, 5_000)["decision"])
        conn.close()

    threads = [threading.Thread(target=attempt) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count("allow") == 10
    assert set(results) <= {"allow", "deny", "hold"}
    rows = ledger.contract_rows(ledger.connect(db_path))
    assert sum(r["amount_cents"] for r in rows[1:] if r["decision"] == "allow") == 50_000
