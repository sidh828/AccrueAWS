"""Cedar is stateless (PRIMER.md 1.3-1.5); this file proves authorize.py is
the thing that actually keeps score, and that it fails closed rather than
open when Cedar can't be trusted.
"""

from datetime import datetime, timezone

import pytest

from src import authorize, ledger
from src.authorize import _ask_cedar


@pytest.fixture
def conn():
    return ledger.connect(":memory:")


def test_50x_9999_eventually_denies(conn):
    """PRIMER.md's motivating example: no single $9,999 transfer looks like
    a problem, but the running total does. Cedar can't see the total -
    authorize.py must catch it once cumulative spend crosses $10,000.
    """
    decisions = [
        authorize.authorize_transfer(conn, "sess-001", "acct-1234", 9999)
        for _ in range(5)
    ]

    # 9999, 19998, 29997, ... - crosses 10000 on the second transfer.
    assert decisions == ["ALLOW", "DENY", "DENY", "DENY", "DENY"]


def test_denied_attempts_do_not_inflate_the_total(conn):
    """A burst of rejected requests must not itself push a session's
    cumulative cost over budget - only ALLOWed amounts count toward future
    totals. But since src/breaker.py, that's no longer the whole story: the
    first DENY trips the circuit breaker for this scope, and a tripped
    scope stays denied - regardless of remaining cumulative-cost headroom -
    until a human logs an explicit override. This test now proves both
    halves: the breaker's stronger default, and that an override really
    does hand control back to the headroom-based check.
    """
    authorize.authorize_transfer(conn, "sess-001", "acct-1234", 9999)  # ALLOW
    for _ in range(10):
        authorize.authorize_transfer(conn, "sess-001", "acct-1234", 9999)  # DENY, trips the breaker

    # Cumulative cost alone still has 1 (10000 - 9999) of headroom left, but
    # the breaker is tripped - denied outright without even asking Cedar.
    decision = authorize.authorize_transfer(conn, "sess-001", "acct-1234", 1)
    assert decision == "DENY"

    # An explicit override resets the breaker - the headroom-based check
    # runs again, and this $1 request fits in what's left.
    ledger.insert_override(
        conn, datetime.now(timezone.utc).isoformat(), "sess-001", "sid",
        "test: confirming override un-trips the breaker",
    )
    conn.commit()
    decision = authorize.authorize_transfer(conn, "sess-001", "acct-1234", 1)
    assert decision == "ALLOW"


def test_budget_is_shared_across_sessions_under_the_same_scope(conn):
    """The whole point of scope_id: two different session_ids sharing one
    scope_id share one budget. $6000 in sess-A alone would fit; $6000 more
    in sess-B alone would fit too - but together, under the same scope,
    they cross $10,000 and the second one must DENY.
    """
    first = authorize.authorize_transfer(
        conn, "sess-A", "acct-1234", 6000, scope_id="agent-a"
    )
    second = authorize.authorize_transfer(
        conn, "sess-B", "acct-1234", 6000, scope_id="agent-a"
    )
    assert (first, second) == ("ALLOW", "DENY")


@pytest.mark.parametrize("amount", [-50000, -0.01, float("nan"), float("inf")])
def test_invalid_amounts_are_rejected_and_not_logged(conn, amount):
    """Regression test for the negative-amount bypass: a -$50,000 transfer
    used to be ALLOWed and logged, lowering the running total so a $59,000
    transfer right after it was ALLOWed too. Malformed amounts must raise
    before anything is written - a logged row would count toward totals.
    """
    with pytest.raises(ValueError, match="amount_usd"):
        authorize.authorize_transfer(conn, "sess-001", "acct-1234", amount)
    assert ledger.list_events(conn) == []

    # The budget is untouched: the follow-up transfer that used to slip
    # through on borrowed headroom is still over $10,000.
    assert authorize.authorize_transfer(conn, "sess-001", "acct-1234", 59000) == "DENY"


def test_new_task_under_the_same_home_does_not_get_a_fresh_budget(conn):
    """Regression test for the scope-hopping bypass: the task segment of a
    scope path is free-form, so when each task had its own budget, three
    $9,999 transfers under three made-up task names were all ALLOWed. They
    share agent-a's budget now.
    """
    decisions = [
        authorize.authorize_transfer(
            conn, "sess-001", "acct-1234", 9999, scope_id=f"agent-a/task-{i}"
        )
        for i in range(3)
    ]
    assert decisions == ["ALLOW", "DENY", "DENY"]


def test_deny_in_one_task_trips_its_siblings(conn):
    """The breaker is enforced at the home too: after a DENY in task-x, a
    $1 request from a brand-new sibling task is denied outright, even
    though agent-a still has headroom. An override logged against the home
    resets it.
    """
    authorize.authorize_transfer(conn, "s1", "acct-1234", 6000, scope_id="agent-a/task-x")
    assert authorize.authorize_transfer(
        conn, "s1", "acct-1234", 6000, scope_id="agent-a/task-x"
    ) == "DENY"
    assert authorize.authorize_transfer(
        conn, "s2", "acct-1234", 1, scope_id="agent-a/task-y"
    ) == "DENY"

    ledger.insert_override(
        conn, datetime.now(timezone.utc).isoformat(), "agent-a", "sid",
        "test: confirming a home-level override un-trips every task",
    )
    conn.commit()
    assert authorize.authorize_transfer(
        conn, "s2", "acct-1234", 1, scope_id="agent-a/task-y"
    ) == "ALLOW"


def test_other_homes_are_unaffected(conn):
    """Rolling up to the home must not leak across homes: agent-a being
    over budget and tripped says nothing about agent-b."""
    authorize.authorize_transfer(conn, "s1", "acct-1234", 9999, scope_id="agent-a/task-x")
    authorize.authorize_transfer(conn, "s1", "acct-1234", 9999, scope_id="agent-a/task-x")
    assert authorize.authorize_transfer(
        conn, "s2", "acct-1234", 9999, scope_id="agent-b/task-x"
    ) == "ALLOW"


def test_session_id_with_a_slash_is_not_split_into_a_home(conn):
    """Without an explicit scope_id, the session_id doubles as the scope.
    Splitting it on "/" would make unrelated sessions "user/123" and
    "user/456" share one home budget, so it's rejected before anything is
    logged."""
    with pytest.raises(ValueError, match="pass scope_id explicitly"):
        authorize.authorize_transfer(conn, "user/123", "acct-1234", 9999)
    assert ledger.list_events(conn) == []


def test_session_id_with_a_slash_is_fine_with_an_explicit_scope(conn):
    assert authorize.authorize_transfer(
        conn, "user/123", "acct-1234", 9999, scope_id="user-123"
    ) == "ALLOW"
    assert authorize.authorize_transfer(
        conn, "user/456", "acct-1234", 9999, scope_id="user-456"
    ) == "ALLOW"


def test_scope_without_a_home_is_rejected(conn):
    with pytest.raises(ValueError, match="home segment"):
        authorize.authorize_transfer(conn, "s1", "acct-1234", 1, scope_id="/task-x")
    assert ledger.list_events(conn) == []


def test_exactly_10000_is_allowed(conn):
    """Documents current behavior: budget.cedar's forbid triggers on
    `context.cumulative_cost > 10000`, so a total of exactly $10,000 is
    ALLOWed, not blocked. If the intent was an inclusive $10,000 cap, the
    policy needs `>=` instead - flagging here so a policy change shows up
    as a failing test, not a silent behavior change.
    """
    decision = authorize.authorize_transfer(conn, "sess-001", "acct-1234", 10000)
    assert decision == "ALLOW"


@pytest.mark.parametrize("amount, expected", [
    (10000.4, "DENY"),   # round() used to make this 10000 and ALLOW it
    (10000.5, "DENY"),   # ...and this one too (banker's rounding to even)
    (10000.01, "DENY"),
    (9999.99, "ALLOW"),
])
def test_fractional_totals_over_the_cap_are_denied(conn, amount, expected):
    """Regression test for the rounding edge: Cedar only takes whole
    dollars, and rounding to nearest let totals up to $10,000.50 through a
    `> 10000` check. Anything over the cap by a cent or more must DENY.
    """
    assert authorize.authorize_transfer(conn, "sess-001", "acct-1234", amount) == expected


def test_float_drift_does_not_deny_a_total_exactly_at_the_cap(conn):
    """The other side of rounding up: these seven amounts total exactly
    $10,000.00, but in floating point the running total comes out as
    10000.000000000002. Rounding that straight up would give 10001 and
    DENY the last transfer even though the policy allows exactly $10,000.
    """
    for amount in [1832.41, 710.49, 2559.53, 358.12, 2680.03, 1671.63]:
        assert authorize.authorize_transfer(conn, "sess-001", "acct-1234", amount) == "ALLOW"

    assert authorize.authorize_transfer(conn, "sess-001", "acct-1234", 187.79) == "ALLOW"


def test_cedar_policy_error_fails_closed():
    """Regression test for the fail-open bug: Cedar drops a policy that
    errors while evaluating (e.g. a context attribute typo) instead of
    aborting, and still exits 0. A context shape the policy doesn't
    recognize must raise, never silently return ALLOW.
    """
    with pytest.raises(RuntimeError, match="silently dropped"):
        _ask_cedar(
            'Session::"sess-001"',
            'Action::"transfer"',
            'Account::"acct-1234"',
            {"cumulative_kost": 50000},  # typo: not a real context attribute
        )


def test_clean_allow_and_deny_still_work():
    assert _ask_cedar(
        'Session::"sess-001"', 'Action::"transfer"', 'Account::"acct-1234"',
        {"cumulative_cost": 500},
    ) == "ALLOW"
    assert _ask_cedar(
        'Session::"sess-001"', 'Action::"transfer"', 'Account::"acct-1234"',
        {"cumulative_cost": 20000},
    ) == "DENY"


@pytest.mark.parametrize("entity_id", ['has"quote', "back\\slash", 'x" || true', '\\"', "émoji🙂"])
def test_quotes_and_backslashes_in_ids_are_escaped_for_cedar(conn, entity_id):
    """session_id and resource go inside Cedar string literals. Unescaped, a
    `"` ended the literal early and the request failed to parse - and once a
    policy reads principal or resource, it could change what's being asked.
    Escaped, they're just part of the id and logged as given."""
    assert authorize.authorize_transfer(conn, entity_id, entity_id, 100) == "ALLOW"
    [event] = ledger.list_events(conn)
    assert event[2] == entity_id and event[5] == entity_id


@pytest.mark.parametrize("field", ["session_id", "resource"])
@pytest.mark.parametrize("bad", ["tab\there", "new\nline", "nul\x00"])
def test_control_characters_in_ids_are_rejected_and_not_logged(conn, field, bad):
    ids = {"session_id": "sess-001", "resource": "acct-1234"} | {field: bad}
    with pytest.raises(ValueError, match="control characters"):
        authorize.authorize_transfer(conn, ids["session_id"], ids["resource"], 100)
    assert ledger.list_events(conn) == []


def test_entity_uid_escapes_exactly_quotes_and_backslashes():
    assert authorize._entity_uid("Account", 'a"b\\c') == 'Account::"a\\"b\\\\c"'
    assert authorize._entity_uid("Account", "plain-id") == 'Account::"plain-id"'
