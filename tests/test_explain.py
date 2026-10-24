"""guard/explain.py: every decision gets a plain-English sentence built from
the numbers the guard logged, and a writer (an AI) is only believed when
every number it uses checks out against them."""

from datetime import datetime, timedelta, timezone

import pytest

from guard import authorize, explain, ledger

pytestmark = pytest.mark.cedar

BILLS = ["mom", "bills-agent"]
TOOLS = {"gift_card": "buy_gift_card", "transfer": "send_zelle"}


@pytest.fixture
def conn():
    c = ledger.connect(":memory:")
    long_ago = datetime.now(timezone.utc) - timedelta(days=60)
    for payee, category, amount in [("grocer.example", "groceries", 100),
                                    ("giftcards.example", "gift_card", 100)]:
        ledger.insert_event(c, ledger.utc_timestamp(long_ago), "s0", "pay", payee, amount,
                            "ALLOW", scope_id="mom/bills-agent", payee=payee, category=category)
    ledger.insert_event(c, ledger.utc_timestamp(long_ago + timedelta(days=30)), "s0", "pay",
                        "columbia-gas.example", 2_980, "ALLOW", scope_id="mom/bills-agent",
                        payee="columbia-gas.example", category="utility")
    c.commit()
    return c


def pay(conn, amount, payee="grocer.example", category="groceries", tainted=False):
    response = authorize.authorize_payment(
        conn, person="mom", chain=BILLS, tool=TOOLS.get(category, "pay_bill"),
        amount_cents=amount, payee=payee, category=category, session_id="s1", tainted=tainted)
    return ledger.get_event(conn, response["event_id"])


def said(event):
    text = explain.template(event)
    assert explain.check(text, event), text  # the template never fails its own check
    assert "cedar" not in text.lower() and "ledger" not in text.lower()
    return text


def test_every_decision_reads_in_plain_english(conn):
    assert said(pay(conn, 12_000)) == "Allowed: $120.00 to grocer.example."
    assert said(pay(conn, 4_000, "dr-patel.example", "medical")) == (
        "Allowed: $40.00 to dr-patel.example, the first payment to them.")
    assert said(pay(conn, 3_310, "columbia-gas.example", "utility")) == (
        "Allowed: $33.10 to columbia-gas.example, a regular bill in line with last time.")
    assert said(pay(conn, 4_420, "columbia-gas.example", "utility")) == (
        "Waiting for you: $44.20 to columbia-gas.example is more than 20% over last "
        "time ($33.10).")
    assert said(pay(conn, 45_000, "giftcards.example", "gift_card")) == (
        "Stopped: that would make $450.00 in gift cards in 24 hours. The limit is $100.00.")
    assert said(pay(conn, 30_000, "zelle:new-contact", "transfer")) == (
        "Stopped: $300.00 is a first payment to zelle:new-contact, and a first payment to "
        "someone new is limited to $200.00.")
    assert said(pay(conn, 35_000)) == (
        "Waiting for you: $350.00 to grocer.example would make $510.00 in 24 hours, over "
        "the $500.00 limit.")


def test_after_a_scam_flag_the_sentence_says_so(conn):
    assert said(pay(conn, 5_000, "giftcards.example", "gift_card", tainted=True)) == (
        "Waiting for you: a $50.00 gift card after a suspicious message needs your OK.")
    assert said(pay(conn, 15_000, "atty-r-mendez.example", "transfer", tainted=True)) == (
        "Stopped: $150.00 to atty-r-mendez.example would make $150.00 in 24 hours. The "
        "limit after a suspicious message is $100.00.")


def test_the_breaker_and_a_broken_engine(conn, monkeypatch, tmp_path):
    for i in range(3):
        pay(conn, 30_000, f"stranger-{i}.example", "transfer")
    assert said(pay(conn, 1_000)) == (
        "Waiting for you: payments are paused after 3 stopped attempts in 10 minutes.")
    monkeypatch.setattr(authorize, "CEDAR_BIN", str(tmp_path / "no-cedar"))
    assert said(pay(conn, 1_000)) == (
        "Waiting for you: the safety check couldn't run, so $10.00 to grocer.example "
        "wasn't paid.")


def test_the_family_answer_reads_as_theirs(conn):
    held = pay(conn, 5_000, "giftcards.example", "gift_card", tainted=True)
    approved = ledger.get_event(conn, authorize.resolve(conn, held["id"], "approve", "daughter"))
    assert said(approved) == "Allowed: you approved $50.00 to giftcards.example."
    rows = ledger.contract_rows(conn)
    assert rows[-1]["explanation"] == "Allowed: you approved $50.00 to giftcards.example."


def test_a_writer_is_used_only_when_its_numbers_check_out(conn):
    event = pay(conn, 45_000, "giftcards.example", "gift_card")

    def honest(facts):
        return ("Gift card stopped: $450.00 in gift cards in 24 hours is over the "
                "$100.00 limit.")

    def invents(facts):
        return "Gift card stopped: Mom already spent $900.00 on gift cards today."

    def rounds(facts):
        return "Stopped: about $500 in gift cards, over the $100.00 limit."

    def crashes(facts):
        raise TimeoutError("model timed out")

    assert explain.explain(event, writer=honest) == honest(None)
    template = explain.template(event)
    assert explain.explain(event, writer=invents) == template
    assert explain.explain(event, writer=rounds) == template
    assert explain.explain(event, writer=crashes) == template
    assert explain.explain(event, writer=lambda f: "") == template


def test_the_checker_reads_counts_too(conn):
    event = pay(conn, 12_000)
    assert explain.check("Allowed: $120.00 to grocer.example.", event)
    assert not explain.check("Allowed: $120.00, the 7th payment this week.", event)
    assert not explain.check("Allowed: $120.01 to grocer.example.", event)
    assert not explain.check("x" * 401, event)
