"""The guarantees we defend on the live call, checked against a whole
ledger after the fact - not decision by decision, but "did anything that
went through break a rule?". The property, concurrency and chaos tests all
end with broken(conn) == [].

Each guarantee is about what the guard itself let through (ALLOW rows that
don't resolve a hold). A payment the family approved went through with
their OK, so it's never a breach - but it still counts toward the totals
the guard has to respect afterwards, exactly as in the guard.
"""

from datetime import datetime, timedelta

from guard import authorize, ledger

DAY, MONTH, BREAKER = timedelta(hours=24), timedelta(days=30), timedelta(minutes=10)


def when(event):
    return datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")


def broken(conn):
    """Every way the ledger breaks a guarantee, as readable strings."""
    events = [ledger.get_event(conn, i) for (i,) in conn.execute("SELECT id FROM events ORDER BY id")]
    allowed = [e for e in events if e["decision"] == "ALLOW"]
    limits = authorize.FAMILY_LIMITS
    first = {}  # (person, payee) -> first allowed event
    for e in allowed:
        first.setdefault((e["home"], e["payee"]), e)
    overrides = conn.execute("SELECT scope_id, after_event_id FROM overrides").fetchall()
    problems = []

    for e in allowed:
        context = e["context"]
        if e["resolves"] is not None or context is None:
            continue  # the family's OK, or history from before the guard
        t, home, tainted = when(e), e["home"], context["tainted"]
        label = f"event {e['id']} ({e['amount_cents']} to {e['payee']})"
        mine = [x for x in allowed if x["home"] == home and x["id"] <= e["id"]]

        def total(rows):
            return sum(x["amount_cents"] for x in rows)

        # Never more than the day's limit ($100 after a scam flag), leaving
        # out known bills and the family's approvals.
        day = [x for x in mine if when(x) >= t - DAY and x["resolves"] is None
               and not (x["context"] or {}).get("known_bill")]
        cap = limits["day_flagged" if tainted else "day"]
        if not context["known_bill"] and total(day) > cap:
            problems.append(f"{label}: {total(day)} in 24 h, over {cap}")

        # Never more than $100 of gift cards in 24 hours; none after a flag.
        if e["category"] == "gift_card":
            gifts = [x for x in mine if when(x) >= t - DAY and x["category"] == "gift_card"]
            if tainted or total(gifts) > limits["gift_card_day"]:
                problems.append(f"{label}: gift cards {total(gifts)} in 24 h"
                                f"{' after a scam flag' if tainted else ''}")

        # A first payment to someone new: at most $200, and none after a flag.
        if first[(home, e["payee"])]["id"] == e["id"]:
            if tainted or e["amount_cents"] > limits["new_payee_first"]:
                problems.append(f"{label}: first payment to a new payee")

        # Payees first paid in the last 30 days: at most $500 together.
        if when(first[(home, e["payee"])]) >= t - MONTH:
            recent = [x for x in mine if when(x) >= t - MONTH
                      and when(first[(home, x["payee"])]) >= t - MONTH]
            cap = limits["recent_payees_flagged" if tainted else "recent_payees"]
            if total(recent) > cap:
                problems.append(f"{label}: {total(recent)} to recent payees in 30 days")

        # Someone new: at most $200 in their first 30 days (the family's
        # approvals aside), so a $1 "verification" can't unlock a big payment.
        first_at = when(first[(home, e["payee"])])
        if first_at >= t - MONTH:
            payee_rows = [x for x in mine if x["payee"] == e["payee"] and when(x) >= first_at
                          and x["resolves"] is None]
            if total(payee_rows) > limits["new_payee_first"]:
                problems.append(f"{label}: {total(payee_rows)} to a payee in its first 30 days")

        # A known bill: at most last time plus 20%, and once a cycle - not if
        # the payee was already paid in the last 20 days.
        if context["known_bill"]:
            if e["amount_cents"] * 5 > context["last_bill"] * 6:
                problems.append(f"{label}: known bill over last time + 20%")
            earlier = [x for x in mine if x["payee"] == e["payee"] and x["id"] < e["id"]
                       and when(x) > t - timedelta(days=20)]
            if earlier:
                problems.append(f"{label}: a known bill paid twice in one cycle")

        # Nothing goes through while the breaker is tripped.
        reset = max((a for s, a in overrides if s == home and a < e["id"]), default=0)
        denials = [x for x in events if x["home"] == home and x["decision"] == "DENY"
                   and x["resolves"] is None and reset < x["id"] < e["id"]
                   and when(x) >= t - BREAKER]
        if len(denials) >= limits["breaker_denials_flagged" if tainted else "breaker_denials"]:
            problems.append(f"{label}: allowed with {len(denials)} denials in 10 min")

    # Exactly one payout for every payment that went through - allowed by
    # the guard, or held and then approved - and none for anything else.
    payouts = {e: n for e, n in conn.execute(
        "SELECT event_id, COUNT(*) FROM payouts GROUP BY event_id")}
    paid = {e["id"] for e in allowed if e["resolves"] is None and e["context"] is not None}
    paid |= {e["resolves"] for e in allowed if e["resolves"] is not None}
    if set(payouts) != paid or any(n != 1 for n in payouts.values()):
        problems.append(f"payouts don't match payments: {sorted(set(payouts) ^ paid)[:5]}")

    # Nothing allowed when the rules engine couldn't answer.
    for e in events:
        if e["rule"] == authorize.GUARD_UNAVAILABLE and e["decision"] != "HOLD":
            problems.append(f"event {e['id']}: {e['decision']} without the rules engine")

    chain = ledger.verify(conn)
    if not chain["ok"]:
        problems.append(f"hash chain broken: {chain}")
    return problems
