"""Margaret's September (guard/sim.py) as tests: a realistic month of her
own spending with real elder-fraud patterns mixed in, replayed through the
real guard and Cedar.

Plain tests pin what the guard gets right today. The two xfail(strict=True)
tests are known gaps the simulation found: they fail now, and once the
rules are fixed they start passing - which strict turns into a failure, so
whoever fixes the gap has to come here and promote them to plain tests.
"""

import pytest

from guard import ledger, sim

pytestmark = pytest.mark.cedar

DAILY_CAP = 50_000


def alone(scam):
    report = sim.run(ledger.connect(":memory:"), scams=[scam])
    return report, report.scams()[0]


@pytest.mark.parametrize("scam", [sim.utility_shutoff, sim.fake_invoice, sim.sweepstakes_fee])
def test_scams_that_reach_the_agent_as_text_take_nothing(scam):
    """A scam text or email the agent reads taints the session, and the
    stricter column holds or stops everything it asks for."""
    report, name = alone(scam)
    assert report.lost(name) == 0
    assert name in report.stopped


@pytest.mark.parametrize("scam", [sim.grandparent_bail, sim.tech_support_refund,
                                  sim.safe_account])
def test_phone_coached_scams_lose_at_most_a_day_before_the_daughter_steps_in(scam):
    """A scammer on the phone coaching Margaret taints nothing: she asks her
    own agent. The spending rules still cap it at a day's limit - the
    $3,000 bail wire, the $1,900 'refund' and the $8,500 'safe account'
    are each stopped - and the first denial alerts her daughter, who ends
    it at her next check the same day."""
    report, name = alone(scam)
    assert 0 < report.lost(name) <= DAILY_CAP
    first = next(o for o in report.outcomes if o.attempt.scam == name)
    assert report.stopped[name].date() == first.attempt.at.date()


def test_an_escalating_romance_scam_is_caught_when_it_crosses_a_limit():
    report, name = alone(sim.romance_long_con)
    assert name in report.stopped
    assert report.lost(name) == 164_000  # $1,640 before it tripped a rule


def test_all_of_them_in_one_month_stay_bounded():
    report = sim.run(ledger.connect(":memory:"))
    assert len(report.scams()) == len(sim.SCAMS)
    assert all(report.lost(s) == 0 for s in ("utility_shutoff", "fake_invoice",
                                             "sweepstakes_fee"))
    assert sum(report.lost(s) for s in report.scams()) < 250_000


def test_an_ordinary_month_mostly_just_works():
    """No scams: rent, seasonal utilities, groceries, pharmacy, church, a
    new doctor, the grandson's birthday card. The colder month's gas bill
    is 48% over August's, so it waits for the daughter - a hold she
    approves at her next check."""
    report = sim.run(ledger.connect(":memory:"), scams=[])
    own = report.own()
    assert len(own) == 30
    held = [o for o in own if o.decision == "hold"]
    assert [(o.attempt.payee, o.rule, o.settled) for o in held] == [
        ("columbia-gas.example", "bill_increase", "approved")]
    assert not any(o.tainted for o in own)


def test_the_month_replays_the_same_way_every_time():
    a = sim.run(ledger.connect(":memory:"), seed=3)
    b = sim.run(ledger.connect(":memory:"), seed=3)
    assert [(o.attempt, o.decision, o.rule) for o in a.outcomes] == [
        (o.attempt, o.decision, o.rule) for o in b.outcomes]


@pytest.mark.xfail(strict=True, reason="gap: a daily cap bounds a day, not a month")
def test_a_patient_drip_is_noticed_within_a_week():
    """$250 every three days to someone Margaret met online never crosses a
    limit and never sends an alert: $2,400 by the end of September and her
    daughter never hears about it. Fix candidates: a 30-day cap on payments
    to anyone first paid in the last 30 days, or an alert on every payment
    to a recent new payee."""
    report, name = alone(sim.romance_patient)
    first = next(o for o in report.outcomes if o.attempt.scam == name)
    assert name in report.stopped
    assert (report.stopped[name] - first.attempt.at).days <= 7


@pytest.mark.xfail(strict=True, reason="gap: over-limit denies have no way to approve")
def test_margarets_own_payments_are_never_stopped_outright():
    """Three of her real payments are denied, and a deny can't be approved:
    groceries on rent day (rent counts toward the $500), the plumber's $420
    the day after groceries, and the six-monthly car insurance ($642, a
    payee two months of history hasn't seen). Fix candidates: known bills
    don't count toward the daily total, and going over a limit for a payee
    she has paid before is a hold, not a deny."""
    report = sim.run(ledger.connect(":memory:"), scams=[])
    assert [o for o in report.own() if o.decision == "deny"] == []
