"""Cross-session scopes: a scope_id is the durable identity that outlives
one session_id. NOTES.md "Ideas" has the design writeup; these are the
target behavior for aggregates.cumulative_cost_for_scope, which is
currently a TODO stub - this file is expected to fail until it's written.
"""

from src import aggregates, ledger


def conn():
    return ledger.connect(":memory:")


def test_scope_rolls_up_multiple_sessions():
    c = conn()
    ledger.insert_event(c, "2026-01-01T00:00:00+00:00", "sess-001", "transfer",
                         "acct-1", 4000, "ALLOW", scope_id="agent-a")
    ledger.insert_event(c, "2026-01-01T00:05:00+00:00", "sess-002", "transfer",
                         "acct-1", 4000, "ALLOW", scope_id="agent-a")
    c.commit()

    # Two different sessions, same scope - the whole point of a scope.
    assert aggregates.cumulative_cost_for_scope(c, "agent-a") == 8000


def test_scope_ignores_other_scopes():
    c = conn()
    ledger.insert_event(c, "2026-01-01T00:00:00+00:00", "sess-001", "transfer",
                         "acct-1", 4000, "ALLOW", scope_id="agent-a")
    ledger.insert_event(c, "2026-01-01T00:00:00+00:00", "sess-002", "transfer",
                         "acct-1", 9000, "ALLOW", scope_id="agent-b")
    c.commit()

    assert aggregates.cumulative_cost_for_scope(c, "agent-a") == 4000


def test_scope_ignores_denied_attempts():
    c = conn()
    ledger.insert_event(c, "2026-01-01T00:00:00+00:00", "sess-001", "transfer",
                         "acct-1", 9000, "ALLOW", scope_id="agent-a")
    ledger.insert_event(c, "2026-01-01T00:05:00+00:00", "sess-002", "transfer",
                         "acct-1", 5000, "DENY", scope_id="agent-a")
    c.commit()

    assert aggregates.cumulative_cost_for_scope(c, "agent-a") == 9000


def test_scope_respects_the_since_window():
    c = conn()
    # a year-old event
    ledger.insert_event(c, "2025-01-01T00:00:00+00:00", "sess-001", "transfer",
                         "acct-1", 9000, "ALLOW", scope_id="agent-a")
    # a recent one
    ledger.insert_event(c, "2026-01-01T00:00:00+00:00", "sess-002", "transfer",
                         "acct-1", 500, "ALLOW", scope_id="agent-a")
    c.commit()

    total = aggregates.cumulative_cost_for_scope(
        c, "agent-a", since="2025-06-01T00:00:00+00:00"
    )
    assert total == 500
