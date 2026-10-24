"""Margaret's September (guard/sim.py) as tests: a realistic month of her
own spending with real elder-fraud patterns mixed in, replayed through the
real guard and Cedar.

The two gaps the simulation first found - a patient drip nobody noticed,
and her own payments denied with no way to approve them - were closed by
the recent-payee cap, the `notice` FYIs, and the known-bill and
known-payee changes (#1). Their tests below are plain tests now.
"""

import pytest

from guard import ledger, sim

pytestmark = pytest.mark.cedar

DAILY_CAP = 50_000


def alone(scam, reads_notices=True):
    report = sim.run(ledger.connect(":memory:"), scams=[scam], reads_notices=reads_notices)
    return report, report.scams()[0]


def first_try(report, name):
    return next(o for o in report.outcomes if o.attempt.scam == name)


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
    assert report.stopped[name].date() == first_try(report, name).attempt.at.date()


@pytest.mark.parametrize("scam", [sim.romance_long_con, sim.romance_patient])
def test_a_romance_scam_is_noticed_after_the_first_payment(scam):
    """The first payment to someone new goes through - and sends the
    daughter an FYI. She calls Mom that evening."""
    report, name = alone(scam)
    assert report.lost(name) == 15_000
    assert report.stopped[name].date() == first_try(report, name).attempt.at.date()


def test_a_patient_drip_is_noticed_within_a_week_even_without_the_fyis():
    """$250 every three days never crosses a day's limit. Before the
    recent-payee caps it took $2,400 in September and was never seen. Now,
    even if the daughter ignores every FYI, the second payment passes $200
    to someone first paid this month, waits for her, and she ends it."""
    report, name = alone(sim.romance_patient, reads_notices=False)
    assert report.lost(name) == 15_000
    assert (report.stopped[name] - first_try(report, name).attempt.at).days < 7


def test_all_of_them_in_one_month_take_less_than_a_days_limit():
    """Eight scams in one month. They share the recent-payee cap, so once the
    romance scams' first payments are in, the bail 'clerks' and the bitcoin
    ATM wait for the daughter instead of getting through."""
    report = sim.run(ledger.connect(":memory:"))
    assert len(report.scams()) == len(sim.SCAMS)
    assert all(scam in report.stopped for scam in report.scams())
    assert sum(report.lost(s) for s in report.scams()) <= DAILY_CAP


def test_margarets_own_payments_are_never_stopped_outright():
    """No scams: rent, seasonal utilities, groceries, pharmacy, church, a
    new doctor, the plumber, the six-monthly car insurance, the grandson's
    birthday card. Nothing is denied. Three wait for the daughter, who
    approves each at her next check: the first cold month's gas bill (48%
    over August's), the insurance ($642, over the day's $500), and the
    pharmacy on the day the plumber was paid."""
    report = sim.run(ledger.connect(":memory:"), scams=[])
    own = report.own()
    assert len(own) == 30
    assert [o for o in own if o.decision == "deny"] == []
    held = [(o.attempt.payee, o.rule, o.settled) for o in own if o.decision == "hold"]
    assert held == [
        ("columbia-gas.example", "bill_increase", "approved"),
        ("cvs.example", "daily_cap_needs_approval", "approved"),
        ("state-farm.example", "daily_cap_needs_approval", "approved"),
    ]
    assert not any(o.tainted for o in own)


def test_the_month_replays_the_same_way_every_time():
    a = sim.run(ledger.connect(":memory:"), seed=3)
    b = sim.run(ledger.connect(":memory:"), seed=3)
    assert [(o.attempt, o.decision, o.rule) for o in a.outcomes] == [
        (o.attempt, o.decision, o.rule) for o in b.outcomes]
