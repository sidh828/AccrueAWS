"""Cedar is stateless (PRIMER.md 1.3-1.5); this file proves authorize.py is
the thing that actually keeps score, and that it fails closed rather than
open when Cedar can't be trusted.

Every amount is integer cents: 999_900 is $9,999, and budget.cedar's cap of
1000000 is $10,000.
"""

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from guard import authorize, ledger
from guard.authorize import _ask_cedar


@pytest.fixture
def conn():
    return ledger.connect(":memory:")


def test_50x_9999_eventually_denies(conn):
    """PRIMER.md's motivating example: no single $9,999 transfer looks like
    a problem, but the running total does. Cedar can't see the total -
    authorize.py must catch it once cumulative spend crosses $10,000.
    """
    decisions = [
        authorize.authorize_transfer(conn, "sess-001", "acct-1234", 999_900)
        for _ in range(5)
    ]

    # $9,999, $19,998, ... - crosses $10,000 on the second transfer.
    assert decisions == ["ALLOW", "DENY", "DENY", "DENY", "DENY"]


def test_denied_attempts_do_not_inflate_the_total(conn):
    """A burst of rejected requests must not itself push a session's
    cumulative cost over budget - only ALLOWed amounts count toward future
    totals. But since guard/breaker.py, that's no longer the whole story: the
    first DENY trips the circuit breaker for this scope, and a tripped
    scope stays denied - regardless of remaining cumulative-cost headroom -
    until a human logs an explicit override. This test now proves both
    halves: the breaker's stronger default, and that an override really
    does hand control back to the headroom-based check.
    """
    authorize.authorize_transfer(conn, "sess-001", "acct-1234", 999_900)  # ALLOW
    for _ in range(10):
        authorize.authorize_transfer(conn, "sess-001", "acct-1234", 999_900)  # DENY, trips the breaker

    # Cumulative cost alone still has $1 ($10,000 - $9,999) of headroom
    # left, but the breaker is tripped - denied outright without even
    # asking Cedar.
    decision = authorize.authorize_transfer(conn, "sess-001", "acct-1234", 100)
    assert decision == "DENY"

    # An explicit override resets the breaker - the headroom-based check
    # runs again, and this $1 request fits in what's left.
    ledger.insert_override(
        conn, datetime.now(timezone.utc).isoformat(), "sess-001", "sid",
        "test: confirming override un-trips the breaker",
    )
    conn.commit()
    decision = authorize.authorize_transfer(conn, "sess-001", "acct-1234", 100)
    assert decision == "ALLOW"


def test_budget_is_shared_across_sessions_under_the_same_scope(conn):
    """The whole point of scope_id: two different session_ids sharing one
    scope_id share one budget. $6000 in sess-A alone would fit; $6000 more
    in sess-B alone would fit too - but together, under the same scope,
    they cross $10,000 and the second one must DENY.
    """
    first = authorize.authorize_transfer(
        conn, "sess-A", "acct-1234", 600_000, scope_id="agent-a"
    )
    second = authorize.authorize_transfer(
        conn, "sess-B", "acct-1234", 600_000, scope_id="agent-a"
    )
    assert (first, second) == ("ALLOW", "DENY")


@pytest.mark.parametrize("amount", [
    -5_000_000,                     # the negative-amount bypass
    -1,
    999_900.0,                      # money is integer cents: no floats
    0.5,
    float("nan"),
    float("inf"),
    True,                           # bool is an int subclass, but not a cent
    "999900",
    authorize.MAX_AMOUNT_CENTS + 1,
])
def test_invalid_amounts_are_rejected_and_not_logged(conn, amount):
    """Regression test for the negative-amount bypass: a -$50,000 transfer
    used to be ALLOWed and logged, lowering the running total so a $59,000
    transfer right after it was ALLOWed too. Anything that isn't a
    non-negative int number of cents must raise before anything is
    written - a logged row would count toward totals.
    """
    with pytest.raises(ValueError, match="amount_cents"):
        authorize.authorize_transfer(conn, "sess-001", "acct-1234", amount)
    assert ledger.list_events(conn) == []

    # The budget is untouched: the follow-up transfer that used to slip
    # through on borrowed headroom is still over $10,000.
    assert authorize.authorize_transfer(conn, "sess-001", "acct-1234", 5_900_000) == "DENY"


def test_new_task_under_the_same_home_does_not_get_a_fresh_budget(conn):
    """Regression test for the scope-hopping bypass: the task segment of a
    scope path is free-form, so when each task had its own budget, three
    $9,999 transfers under three made-up task names were all ALLOWed. They
    share agent-a's budget now.
    """
    decisions = [
        authorize.authorize_transfer(
            conn, "sess-001", "acct-1234", 999_900, scope_id=f"agent-a/task-{i}"
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
    authorize.authorize_transfer(conn, "s1", "acct-1234", 600_000, scope_id="agent-a/task-x")
    assert authorize.authorize_transfer(
        conn, "s1", "acct-1234", 600_000, scope_id="agent-a/task-x"
    ) == "DENY"
    assert authorize.authorize_transfer(
        conn, "s2", "acct-1234", 100, scope_id="agent-a/task-y"
    ) == "DENY"

    ledger.insert_override(
        conn, datetime.now(timezone.utc).isoformat(), "agent-a", "sid",
        "test: confirming a home-level override un-trips every task",
    )
    conn.commit()
    assert authorize.authorize_transfer(
        conn, "s2", "acct-1234", 100, scope_id="agent-a/task-y"
    ) == "ALLOW"


def test_other_homes_are_unaffected(conn):
    """Rolling up to the home must not leak across homes: agent-a being
    over budget and tripped says nothing about agent-b."""
    authorize.authorize_transfer(conn, "s1", "acct-1234", 999_900, scope_id="agent-a/task-x")
    authorize.authorize_transfer(conn, "s1", "acct-1234", 999_900, scope_id="agent-a/task-x")
    assert authorize.authorize_transfer(
        conn, "s2", "acct-1234", 999_900, scope_id="agent-b/task-x"
    ) == "ALLOW"


def test_scope_names_are_case_insensitive(conn):
    """Regression test: "Mom" and "mom" were two budgets (exact match) that
    still leaked into each other (SQLite's LIKE ignores case), so the same
    person got $10,000 per spelling. Scopes are lowercased on the way in
    and out now: one budget, one breaker, and an override logged under any
    spelling resets it."""
    assert authorize.authorize_transfer(conn, "s1", "acct-1234", 600_000, scope_id="Mom") == "ALLOW"
    assert authorize.authorize_transfer(
        conn, "s2", "acct-1234", 600_000, scope_id="MOM/bills"
    ) == "DENY"
    assert authorize.authorize_transfer(conn, "s3", "acct-1234", 100, scope_id="mom") == "DENY"

    ledger.insert_override(
        conn, datetime.now(timezone.utc).isoformat(), "MoM", "sid",
        "test: an override under another spelling still resets the breaker",
    )
    conn.commit()
    assert authorize.authorize_transfer(conn, "s3", "acct-1234", 100, scope_id="mom") == "ALLOW"


def test_budget_counts_only_the_last_24_hours(conn):
    """Regression test: authorize_transfer never passed a window, so the
    budget was lifetime - $9,999 spent a year ago still blocked $2 today.
    Only the last authorize.BUDGET_WINDOW counts now."""
    now = datetime.now(timezone.utc)
    for hours_ago, amount in [(25, 900_000), (23, 50_000)]:
        ledger.insert_event(
            conn, ledger.utc_timestamp(now - timedelta(hours=hours_ago)), "s0",
            "transfer", "acct-1234", amount, "ALLOW", scope_id="mom",
        )
    conn.commit()

    # 25 hours ago has aged out; 23 hours ago still counts: $500 + $9,500
    # is exactly the $10,000 cap, and one cent more is over it.
    assert authorize.authorize_transfer(conn, "s1", "acct-1234", 950_000, scope_id="mom") == "ALLOW"
    assert authorize.authorize_transfer(conn, "s1", "acct-1234", 1, scope_id="mom") == "DENY"


def test_retrying_a_request_id_is_not_counted_twice(conn):
    """An agent that times out and asks again with the same request_id gets
    the original decision back, and nothing new is logged or counted. If
    the retry had counted, the third request's $6,000 would have been
    measured against $12,000 already spent instead of $6,000."""
    first = authorize.authorize_transfer(
        conn, "s1", "acct-1234", 600_000, scope_id="mom", request_id="req-1"
    )
    retry = authorize.authorize_transfer(
        conn, "s1", "acct-1234", 600_000, scope_id="mom", request_id="req-1"
    )
    assert (first, retry) == ("ALLOW", "ALLOW")
    assert len(ledger.list_events(conn)) == 1

    assert authorize.authorize_transfer(
        conn, "s1", "acct-1234", 400_000, scope_id="mom", request_id="req-2"
    ) == "ALLOW"


def test_reusing_a_request_id_for_a_different_request_raises(conn):
    authorize.authorize_transfer(
        conn, "s1", "acct-1234", 600_000, scope_id="mom", request_id="req-1"
    )
    with pytest.raises(ValueError, match="different request"):
        authorize.authorize_transfer(
            conn, "s1", "acct-1234", 700_000, scope_id="mom", request_id="req-1"
        )
    assert len(ledger.list_events(conn)) == 1


def test_racing_copies_of_one_request_are_logged_once(tmp_path):
    """Ten copies of the same request fired at once (an agent retrying in
    parallel) all get the same decision, and only one row is written: the
    request_id lookup happens inside the write lock."""
    db_path = str(tmp_path / "ledger.db")
    ledger.connect(db_path).close()
    results = []

    def attempt():
        conn = ledger.connect(db_path)
        results.append(authorize.authorize_transfer(
            conn, "s1", "acct-1234", 600_000, scope_id="mom", request_id="req-1"
        ))
        conn.close()

    threads = [threading.Thread(target=attempt) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == ["ALLOW"] * 10
    assert len(ledger.list_events(ledger.connect(db_path))) == 1


def test_policy_path_is_a_parameter(conn, tmp_path):
    """A draft policy can be asked beside the live one (policy replay, the
    other policy packs) without swapping a module global."""
    strict = tmp_path / "strict.cedar"
    strict.write_text(authorize.POLICY_PATH.read_text().replace(
        "context.cumulative_cost > 1000000", "context.cumulative_cost > 10000"
    ))
    assert authorize.authorize_transfer(
        conn, "s1", "acct-1234", 20_000, scope_id="a", policy_path=strict
    ) == "DENY"
    assert authorize.authorize_transfer(conn, "s1", "acct-1234", 20_000, scope_id="b") == "ALLOW"


def test_session_id_with_a_slash_is_not_split_into_a_home(conn):
    """Without an explicit scope_id, the session_id doubles as the scope.
    Splitting it on "/" would make unrelated sessions "user/123" and
    "user/456" share one home budget, so it's rejected before anything is
    logged."""
    with pytest.raises(ValueError, match="pass scope_id explicitly"):
        authorize.authorize_transfer(conn, "user/123", "acct-1234", 999_900)
    assert ledger.list_events(conn) == []


def test_session_id_with_a_slash_is_fine_with_an_explicit_scope(conn):
    assert authorize.authorize_transfer(
        conn, "user/123", "acct-1234", 999_900, scope_id="user-123"
    ) == "ALLOW"
    assert authorize.authorize_transfer(
        conn, "user/456", "acct-1234", 999_900, scope_id="user-456"
    ) == "ALLOW"


def test_scope_without_a_home_is_rejected(conn):
    with pytest.raises(ValueError, match="home segment"):
        authorize.authorize_transfer(conn, "s1", "acct-1234", 100, scope_id="/task-x")
    assert ledger.list_events(conn) == []


def test_exactly_10000_is_allowed(conn):
    """Documents current behavior: budget.cedar's forbid triggers on
    `context.cumulative_cost > 1000000`, so a total of exactly $10,000 is
    ALLOWed, not blocked. If the intent was an inclusive $10,000 cap, the
    policy needs `>=` instead - flagging here so a policy change shows up
    as a failing test, not a silent behavior change.
    """
    decision = authorize.authorize_transfer(conn, "sess-001", "acct-1234", 1_000_000)
    assert decision == "ALLOW"


def test_one_cent_over_the_cap_is_denied(conn):
    """With dollars as floats, Cedar had to be handed a rounded number, and
    rounding let totals up to $10,000.50 through. In integer cents nothing
    is rounded: one cent over is over."""
    assert authorize.authorize_transfer(conn, "s1", "acct-1234", 1_000_001, scope_id="a") == "DENY"
    assert authorize.authorize_transfer(conn, "s1", "acct-1234", 999_999, scope_id="b") == "ALLOW"
    assert authorize.authorize_transfer(conn, "s1", "acct-1234", 2, scope_id="b") == "DENY"


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
            {"cumulative_kost": 5_000_000},  # typo: not a real context attribute
        )


def test_a_hung_cedar_times_out_and_releases_the_lock(tmp_path, monkeypatch):
    """Regression test: the Cedar call had no timeout and runs while the
    ledger's write lock is held, so a hung Cedar blocked every other
    request (they failed with "database is locked" after 5 s) and never
    returned itself. It now times out, logs nothing, and lets the next
    request through."""
    hung = tmp_path / "cedar"
    hung.write_text("#!/bin/sh\nexec sleep 30\n")  # exec: the kill reaches sleep
    hung.chmod(0o755)
    monkeypatch.setattr(authorize, "CEDAR_BIN", str(hung))
    monkeypatch.setattr(authorize, "CEDAR_TIMEOUT_SECONDS", 0.3)

    db_path = str(tmp_path / "ledger.db")
    conn = ledger.connect(db_path)
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="timed out"):
        authorize.authorize_transfer(conn, "sess-001", "acct-1234", 100)
    assert time.monotonic() - started < 5
    assert ledger.list_events(conn) == []

    monkeypatch.setattr(authorize, "CEDAR_BIN", "cedar")
    other = ledger.connect(db_path)
    assert authorize.authorize_transfer(other, "sess-002", "acct-1234", 100) == "ALLOW"


def test_clean_allow_and_deny_still_work():
    assert _ask_cedar(
        'Session::"sess-001"', 'Action::"transfer"', 'Account::"acct-1234"',
        {"cumulative_cost": 50_000},
    ) == "ALLOW"
    assert _ask_cedar(
        'Session::"sess-001"', 'Action::"transfer"', 'Account::"acct-1234"',
        {"cumulative_cost": 2_000_000},
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
