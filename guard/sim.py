"""A month in the life of one household, replayed through the real guard.

    python3 -m guard.sim            # prints the scorecard

The gift-card demo is one scam and one afternoon. This is a fuller test:
Margaret, 78, rents an apartment in Columbus and has a bills agent. The
guard starts with six months of her ordinary bank history (rent, seasonal
utilities, groceries, pharmacy, church, car insurance in March), the way
it would be set up from a bank's statements, and then September is
replayed payment by payment
through authorize.authorize_payment, with eight of the frauds that actually
take older adults' money mixed into it. Everything here is fictional.

Two things make it more than a script:

- The scammers adapt. Denied, they ask for less, split the amount, switch
  to gift cards or crypto, or spread it over new "accounts" - the moves a
  per-request limit invites. They stop when the daughter finds out.
- How the scam reaches Mom matters. A scam text or email that the agent
  reads taints the session ("via" sms or email), so the stricter column
  applies. A scammer on the phone coaching Margaret, who then tells her
  own agent to pay ("via" mom), taints nothing: the request comes from the
  trusted person. Only the spending rules stand in the way. That's the
  hard case, and the realistic one.

The daughter gets a phone alert for every stopped or held payment, and an
FYI for every payment that went through to someone new or recent (the
event row's `notice`). She looks at them at 9:00, 12:30, 18:30 and 21:30.
Then she approves Mom's real payments that were held, denies the scam
ones, calls Mom about any scam she was alerted to (which ends it), clears
the session's taint, and resets the breaker. run(reads_notices=False)
leaves out the FYIs, to show what the rules catch on their own.

The scorecard counts both sides: what each scam took, and what the rules
cost Margaret - her own payments stopped outright (she can't override a
deny) or held until her daughter's next check.
"""

import heapq
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import authorize, ledger

PERSON = "margaret"
AGENT = ["margaret", "bills-agent"]
SEPTEMBER = datetime(2026, 9, 1, tzinfo=timezone.utc)  # a Tuesday
DAUGHTER_CHECKS = (9.0, 12.5, 18.5, 21.5)  # hours of the day she looks at her phone


@dataclass(frozen=True)
class Attempt:
    at: datetime
    payee: str
    category: str
    tool: str
    amount_cents: int
    via: str = "mom"  # "mom": she asked her agent herself; "sms"/"email": untrusted text did
    scam: str = None  # None for Margaret's own spending
    note: str = ""


@dataclass
class Outcome:
    attempt: Attempt
    decision: str  # allow / deny / hold, as the guard answered
    rule: str
    tainted: bool
    event_id: int = None
    settled: str = None  # for a hold: "approved" or "denied" by the daughter
    settled_at: datetime = None


@dataclass
class Report:
    outcomes: list = field(default_factory=list)
    stopped: dict = field(default_factory=dict)  # scam -> when the daughter ended it

    def lost(self, scam):
        """Cents a scam took: allowed outright, or held and then approved."""
        return sum(o.attempt.amount_cents for o in self.outcomes if o.attempt.scam == scam
                   and (o.decision == "allow" or o.settled == "approved"))

    def scams(self):
        return sorted({o.attempt.scam for o in self.outcomes if o.attempt.scam})

    def own(self):
        return [o for o in self.outcomes if o.attempt.scam is None]


def at(day, hour):
    """Day 1 is September 1. Hours are local and fractional (13.5 = 1:30 PM)."""
    return SEPTEMBER + timedelta(days=day - 1, hours=hour)


# --- Margaret's own money ----------------------------------------------------------

def household(month_start, rng, september=False):
    """One month of Margaret's real spending. Bills follow the season;
    groceries, pharmacy and church follow the week."""
    def on(day, hour):
        return month_start + timedelta(days=day - 1, hours=hour)

    month = month_start.month
    out = [
        Attempt(on(1, 9), "maple-court-apartments.example", "rent", "pay_bill", 145_000),
        Attempt(on(3, 10), "medicare-partd.example", "insurance", "pay_bill", 3_480),
        Attempt(on(8, 11), "netflix.example", "subscription", "pay_bill", 1_549),
        Attempt(on(12, 10), "aep-ohio.example", "utility", "pay_bill",
                {3: 11_820, 4: 9_940, 5: 9_310, 6: 11_960, 7: 13_640, 8: 14_210,
                 9: 9_870}[month]),
        # Gas: the first cool month costs more than August's - a real rise.
        Attempt(on(15, 10), "columbia-gas.example", "utility", "pay_bill",
                {3: 9_860, 4: 6_420, 5: 3_980, 6: 3_310, 7: 3_150, 8: 2_980,
                 9: 4_420}[month]),
        Attempt(on(17, 14), "great-clips.example", "personal", "pay_bill", 3_200),
        Attempt(on(20, 10), "spectrum.example", "utility", "pay_bill", 8_999),
        Attempt(on(25, 10), "columbus-water.example", "utility", "pay_bill", 4_610),
    ]
    days = (month_start.replace(month=month % 12 + 1) - month_start).days
    for day in range(1, days + 1):
        weekday = on(day, 0).weekday()  # Monday is 0
        if weekday in (1, 4):  # Tuesday and Friday
            out.append(Attempt(on(day, 16), "kroger.example", "groceries", "pay_bill",
                               rng.randrange(4_000, 11_000)))
        if weekday == 2:  # Wednesday
            out.append(Attempt(on(day, 15), "cvs.example", "pharmacy", "pay_bill",
                               rng.randrange(1_200, 6_500)))
        if weekday == 6:  # Sunday
            out.append(Attempt(on(day, 11), "st-marks-church.example", "donation",
                               "pay_bill", 5_000))
    if month == 3:
        out.append(Attempt(on(18, 10), "state-farm.example", "insurance", "pay_bill", 61_800,
                           note="car insurance, paid every six months"))
    if month == 8:
        out.append(Attempt(on(5, 13), "ace-plumbing.example", "home_repair", "pay_bill", 18_500,
                           note="fixed the kitchen sink"))
    if september:
        out += [
            Attempt(on(9, 9.5), "ohiohealth-clinic.example", "medical", "pay_bill", 4_000,
                    note="new doctor's copay"),
            Attempt(on(16, 10), "ace-plumbing.example", "home_repair", "pay_bill", 42_000,
                    note="water heater valve, same plumber as August"),
            Attempt(on(18, 10), "state-farm.example", "insurance", "pay_bill", 64_200,
                    note="car insurance, paid every six months"),
            Attempt(on(22, 12), "giftcards.example", "gift_card", "buy_gift_card", 5_000,
                    note="grandson's birthday"),
        ]
    return sorted(out, key=lambda a: a.at)


# --- The scams ---------------------------------------------------------------------
#
# Each is a generator: it yields its next attempt and is sent back the
# guard's decision ("allow", "deny" or "hold"), so it can adapt. It's
# dropped as soon as the daughter has ended it.

def romance_long_con():
    """Met online in the spring; "David" works on an oil rig and can't get
    to his own money. Small at first, then steady, never alarming in one
    payment. Margaret sends it herself."""
    t = at(2, 19)
    for amount in (15_000, 38_000, 45_000, 42_000, 48_000, 45_000, 47_500, 49_000,
                   46_000, 48_000, 45_000):
        decision = yield Attempt(t, "david-whitaker-rig.example", "transfer", "send_zelle",
                                 amount, scam="romance_long_con")
        if decision == "deny":
            amount //= 2  # "just send what you can, darling"
            yield Attempt(t + timedelta(hours=1), "david-whitaker-rig.example", "transfer",
                          "send_zelle", amount, scam="romance_long_con")
        t += timedelta(days=2, hours=12)


def romance_patient():
    """The same con, run by someone who has learned where the line is: one
    modest first payment, then $250 every three days. No single payment,
    and no single day, is over any limit."""
    t = at(2, 19)
    for amount in (15_000,) + (25_000,) * 9:
        yield Attempt(t, "james-oduya-medic.example", "transfer", "send_zelle", amount,
                      scam="romance_patient")
        t += timedelta(days=3)


def utility_shutoff():
    """A text: "AEP: your power will be cut off in 30 minutes, pay now." The
    agent reads it, so the session is tainted."""
    t = at(6, 10.25)
    decision = yield Attempt(t, "aep-ohio-billing.example", "utility", "pay_bill", 41_237,
                             via="sms", scam="utility_shutoff")
    if decision != "allow":
        yield Attempt(t + timedelta(minutes=10), "aep-ohio-billing.example", "utility",
                      "pay_bill", 9_500, via="sms", scam="utility_shutoff",
                      note="a smaller 'reconnection fee'")
        yield Attempt(t + timedelta(minutes=25), "giftcards.example", "gift_card",
                      "buy_gift_card", 20_000, via="sms", scam="utility_shutoff",
                      note="'the system is down, use gift cards'")


def grandparent_bail():
    """A call: "Grandma, I'm in jail, don't tell Mom." A fake attorney wants
    bail wired. Margaret tells her agent to pay. When the wire fails, the
    'attorney' has her send smaller amounts to 'his clerks'."""
    t = at(9, 14)
    decision = yield Attempt(t, "atty-r-mendez.example", "transfer", "send_wire", 300_000,
                             scam="grandparent_bail")
    if decision == "allow":
        return
    yield Attempt(t + timedelta(minutes=15), "atty-r-mendez.example", "transfer", "send_wire",
                  150_000, scam="grandparent_bail")
    for i in range(1, 13):
        yield Attempt(t + timedelta(minutes=30 + 10 * i), f"court-clerk-{i}.example",
                      "transfer", "send_zelle", 19_500, scam="grandparent_bail")


def tech_support_refund():
    """A pop-up, then a call from "Microsoft": they 'over-refunded' her
    $1,900 and she must send it back. They're on her screen and tell her
    what to type."""
    t = at(13, 11)
    yield Attempt(t, "ms-refund-desk.example", "transfer", "send_zelle", 190_000,
                  scam="tech_support_refund")
    yield Attempt(t + timedelta(minutes=20), "giftcards.example", "gift_card", "buy_gift_card",
                  50_000, scam="tech_support_refund")
    for i in range(4):
        yield Attempt(t + timedelta(minutes=40 + 30 * i), "giftcards.example", "gift_card",
                      "buy_gift_card", 9_500, scam="tech_support_refund",
                      note="'just under the limit, then wait'")


def fake_invoice():
    """The day the plumber comes, an email 'from Ace Plumbing' with new bank
    details. The agent reads the email, so the session is tainted."""
    t = at(16, 15)
    decision = yield Attempt(t, "ace-plumbing-payments.example", "home_repair", "pay_bill",
                             42_000, via="email", scam="fake_invoice")
    if decision != "allow":
        yield Attempt(t + timedelta(minutes=30), "ace-plumbing-payments.example", "home_repair",
                      "pay_bill", 9_000, via="email", scam="fake_invoice",
                      note="'just the deposit for now'")


def safe_account():
    """A call from 'Social Security': her number was used in a crime, and
    she must move her savings to a 'protected account' or crypto 'for
    safekeeping'. The classic big one."""
    t = at(24, 10.5)
    yield Attempt(t, "ssa-protected-account.example", "transfer", "send_wire", 850_000,
                  scam="safe_account")
    yield Attempt(t + timedelta(minutes=20), "coinflip-bitcoin-atm.example", "crypto",
                  "send_crypto", 200_000, scam="safe_account")
    for i in range(6):
        yield Attempt(t + timedelta(minutes=45 + 25 * i), "coinflip-bitcoin-atm.example",
                      "crypto", "send_crypto", 19_000, scam="safe_account")


def sweepstakes_fee():
    """A text: she's won $2.5 million and just needs to pay the fee."""
    t = at(27, 16)
    decision = yield Attempt(t, "giftcards.example", "gift_card", "buy_gift_card", 25_000,
                             via="sms", scam="sweepstakes_fee")
    if decision != "allow":
        yield Attempt(t + timedelta(minutes=15), "giftcards.example", "gift_card",
                      "buy_gift_card", 9_900, via="sms", scam="sweepstakes_fee")


SCAMS = [romance_long_con, romance_patient, utility_shutoff, grandparent_bail, tech_support_refund,
         fake_invoice, safe_account, sweepstakes_fee]


# --- The month ------------------------------------------------------------------------

def run(conn, seed=0, scams=SCAMS, reads_notices=True):
    """Load six months of history into `conn`, replay September through the
    guard, and return a Report. With `reads_notices` off, the daughter only
    hears about stopped and held payments."""
    rng = random.Random(seed)
    for month in range(3, 9):  # bank history from before the guard: all of it went through
        for a in household(datetime(2026, month, 1, tzinfo=timezone.utc), rng):
            ledger.insert_event(conn, ledger.utc_timestamp(a.at), "history", "pay", a.payee,
                                a.amount_cents, "ALLOW", scope_id="/".join(AGENT),
                                payee=a.payee, category=a.category, tool=a.tool)
    conn.commit()

    report = Report()
    queue, order = [], 0  # (time, order, kind, payload)

    def push(when, kind, payload):
        nonlocal order
        heapq.heappush(queue, (when, order, kind, payload))
        order += 1

    for a in household(SEPTEMBER, rng, september=True):
        push(a.at, "own", a)
    running = {}
    for make in scams:
        gen = make()
        first = next(gen)
        running[first.scam] = gen
        push(first.at, "scam", first)
    for day in range(1, 31):
        for hour in DAUGHTER_CHECKS:
            push(at(day, hour), "check", None)

    tainted_since = None  # untrusted text reached the agent; cleared at her next check
    pending = []  # held outcomes waiting for her
    alerted = set()  # scams she has had an alert about since her last check

    while queue:
        when, _, kind, payload = heapq.heappop(queue)
        if kind == "check":
            for o in pending:
                o.settled = "denied" if o.attempt.scam else "approved"
                o.settled_at = when
                authorize.resolve(conn, o.event_id, "deny" if o.attempt.scam else "approve",
                                  "daughter", now=when)
            for scam in alerted:
                report.stopped.setdefault(scam, when)
                running.pop(scam, None)
            if pending or alerted:
                ledger.insert_override(conn, ledger.utc_timestamp(when), PERSON, "daughter",
                                       "reviewed today's alerts")
                conn.commit()
            pending, alerted, tainted_since = [], set(), None
            continue

        attempt = payload
        if kind == "scam" and attempt.scam not in running:
            continue  # she already called Mom
        if attempt.via != "mom" and tainted_since is None:
            tainted_since = when
        tainted = tainted_since is not None
        response = authorize.authorize_payment(
            conn, person=PERSON, chain=AGENT, tool=attempt.tool,
            amount_cents=attempt.amount_cents, payee=attempt.payee, category=attempt.category,
            session_id="margaret-agent", tainted=tainted, now=when,
            reason=attempt.note or attempt.scam or "",
        )
        outcome = Outcome(attempt, response["decision"], response["rule"], tainted,
                          response["event_id"])
        report.outcomes.append(outcome)
        if outcome.decision == "hold":
            pending.append(outcome)
        if outcome.decision != "allow" and attempt.scam:
            alerted.add(attempt.scam)  # stopped or held: her phone buzzes
        elif reads_notices and attempt.scam and _notice(conn, outcome.event_id):
            alerted.add(attempt.scam)  # went through, but to someone new: an FYI

        if kind == "scam":
            try:
                nxt = running[attempt.scam].send(outcome.decision)
                push(nxt.at, "scam", nxt)
            except StopIteration:
                running.pop(attempt.scam, None)
    return report


def _notice(conn, event_id):
    """The event row's `notice`: set when a payment went through to someone
    new or recent."""
    return ledger.contract_rows(conn, since=event_id - 1)[0]["notice"]


def money(cents):
    return f"${cents / 100:,.2f}"


def scam_line(report, scam):
    tries = [o for o in report.outcomes if o.attempt.scam == scam]
    via = "text/email" if tries[0].attempt.via != "mom" else "phone, Mom asks"
    stop = report.stopped.get(scam)
    ended = f"daughter, {stop:%b %d %H:%M}" if stop else "never noticed"
    return f"{scam:22} {via:16} {len(tries):>5} {money(report.lost(scam)):>10}  {ended}"


def own_lines(report):
    """What the rules cost Margaret's own spending."""
    own = report.own()
    allowed = [o for o in own if o.decision == "allow"]
    held = [o for o in own if o.decision == "hold"]
    denied = [o for o in own if o.decision == "deny"]
    lines = [f"Margaret's own payments in September, no scams: {len(own)}, "
                  f"{money(sum(o.attempt.amount_cents for o in own))}",
              f"  went straight through: {len(allowed)}",
              f"  held until her daughter approved: {len(held)}"]
    for o in held:
        wait = (o.settled_at - o.attempt.at).total_seconds() / 3600
        lines.append(f"    {o.attempt.at:%b %d} {o.attempt.payee:32} {money(o.attempt.amount_cents):>9}"
                     f"  {o.rule}{' (tainted)' if o.tainted else ''}, waited {wait:.1f} h")
    lines.append(f"  stopped outright (no way to approve a deny): {len(denied)}")
    for o in denied:
        lines.append(f"    {o.attempt.at:%b %d} {o.attempt.payee:32} {money(o.attempt.amount_cents):>9}"
                     f"  {o.rule}{' (tainted)' if o.tainted else ''}")
    return lines


def scorecard(seed=0):
    """Each scam on its own (so one can't hide behind another), then all of
    them in the same month, then what the rules cost Margaret's own
    spending in a month with no scams at all."""
    header = f"{'scam':22} {'reached Mom by':16} {'tries':>5} {'lost':>10}  ended"
    lines = ["Each scam alone:", header]
    for make in SCAMS:
        report = run(ledger.connect(":memory:"), seed, scams=[make])
        lines.append(scam_line(report, report.scams()[0]))

    lines += ["", "Each scam alone, rules only (the daughter ignores the FYIs):", header]
    for make in SCAMS:
        report = run(ledger.connect(":memory:"), seed, scams=[make], reads_notices=False)
        lines.append(scam_line(report, report.scams()[0]))

    together = run(ledger.connect(":memory:"), seed)
    lines += ["", "All of them in the same month:", header]
    lines += [scam_line(together, scam) for scam in together.scams()]
    total = sum(together.lost(s) for s in together.scams())
    lines.append(f"{'total':22} {'':16} {'':>5} {money(total):>10}")

    quiet = run(ledger.connect(":memory:"), seed, scams=[])
    lines += [""] + own_lines(quiet)
    return "\n".join(lines)


def main():
    print(scorecard())


if __name__ == "__main__":
    main()
