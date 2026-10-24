"""Attack-table assertions for simulation outcomes and real Cedar-backed evidence."""
import pytest

from agent.attacks.attack_suite import ATTACKS, make_env, run_suite
from agent.attacks.scorer import BLOCKED, CAPPED, ERROR, LEAKED, NOT_RUN
from agent.scenarios import normal_day, parallel_flood
from agent.scenarios.common import SCAM_SMS, UNLABELED_SCAM_SMS as U
from walls.inbound import deterministic_labels


@pytest.fixture(scope="module")
def table():
    return run_suite()


def status(table, attack_prefix, defense):
    (row,) = [c for n, c in table.items() if n.startswith(attack_prefix)]
    return row[defense].status


def test_no_harness_errors(table):
    assert not [(n, d) for n, c in table.items() for d, o in c.items() if o.status == ERROR]


def test_our_guard_leaks_only_disclosed_gaps(table):
    gaps = {a.name for a in ATTACKS if a.known_gap}
    leaks = {n for n, c in table.items() if c["ours"].status == LEAKED}
    assert leaks <= gaps, f"undisclosed leaks: {leaks - gaps}"


def test_baselines_really_fail_the_money_attacks(table):
    """If the per-call check stopped these, the comparison would be meaningless."""
    for name in ("Ten $450", "Slow drip", "Gift cards blocked, switch", "Two sub-agents", "50 requests"):
        assert status(table, name, "per_call") == LEAKED, name


def test_cumulative_attacks_never_exceed_the_daily_cap(table):
    for name in ("Ten $450", "Slow drip", "Gift cards blocked, switch", "Two sub-agents", "50 requests", "Sub-agent fakes"):
        (row,) = [c for n, c in table.items() if n.startswith(name)]
        assert row["ours"].through_cents <= 50_000, name


def test_some_attack_beats_the_label_wall_but_not_ours(table):
    beaten = [n for n, c in table.items() if c["scam_wall"].status == LEAKED and c["ours"].status in (BLOCKED, CAPPED)]
    assert beaten, "need at least one attack that beats the label wall while ours holds"


def test_prompt_only_column_is_never_faked(table):
    assert all(c["prompt_only"].status == NOT_RUN for c in table.values())


def test_unlabeled_scam_text_really_has_no_labels():
    assert deterministic_labels(U) == []
    assert deterministic_labels(SCAM_SMS) != []


def test_normal_day_unaffected_by_every_guard_we_own():
    env = make_env("ours")
    r = normal_day.run(env)
    assert r.through_cents == r.attempted_cents == 17_000


@pytest.mark.parametrize("run", range(10))
def test_fifty_at_once_lands_exactly_on_the_cap(run):
    r = parallel_flood.run(make_env("ours"))
    assert r.through_cents == 50_000 and r.allowed == 10


@pytest.mark.cedar
def test_real_attack_evidence_uses_cedar_and_verifies_ledger():
    table = run_suite(real_guard=True)
    known_gaps = {attack.name for attack in ATTACKS if attack.known_gap}
    leaked = {name for name, cells in table.items() if cells["ours"].status == LEAKED}
    assert leaked <= known_gaps
    for name, cells in table.items():
        outcome = cells["ours"]
        assert outcome.status != ERROR, (name, outcome.detail)
        assert outcome.evidence["backend"] == "real_http_cedar_ledger"
        assert outcome.evidence["cedar_version"]
        integrity = outcome.evidence["ledger_verification"]
        expected_count = integrity["head"]["event_id"] if integrity["head"] else 0
        assert outcome.evidence["event_count"] == expected_count
        if name == "Ledger row edited by hand":
            assert outcome.status == BLOCKED
            assert integrity["ok"] is False
            assert integrity["first_bad_event_id"] == 1
        else:
            assert integrity["ok"] is True, name
    for name in ("Ten $450", "Slow drip", "Gift cards blocked", "Two sub-agents",
                 "50 requests", "Sub-agent fakes"):
        (cells,) = [cells for attack, cells in table.items() if attack.startswith(name)]
        assert cells["ours"].through_cents <= 50_000, name


def test_simulation_report_is_explicitly_labeled():
    from agent.attacks.attack_suite import run_metadata

    metadata = run_metadata(real_guard=False)
    assert metadata["mode"] == "simulation"
    assert metadata["guard_backend"] == "FakeGuard simulation"
    assert "source_worktree_clean" in metadata
