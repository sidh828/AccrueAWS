"""Circuit breaker: once a scope's most recent attempt was denied, every
further request for it should auto-DENY without even asking Cedar, until a
human appends an explicit override. NOTES.md "Ideas" has the design
writeup; these are the target behavior for breaker.is_tripped, which is
currently a TODO stub - this file is expected to fail until it's written.
"""

from src import ledger
from src import breaker


def conn():
    return ledger.connect(":memory:")


def test_new_scope_is_not_tripped():
    c = conn()
    assert breaker.is_tripped(c, "agent-a") is False


def test_scope_is_not_tripped_after_an_allow():
    c = conn()
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 100,
                         "ALLOW", scope_id="agent-a")
    c.commit()
    assert breaker.is_tripped(c, "agent-a") is False


def test_scope_trips_after_a_deny():
    c = conn()
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 100,
                         "DENY", scope_id="agent-a")
    c.commit()
    assert breaker.is_tripped(c, "agent-a") is True


def test_override_after_the_deny_resets_it():
    c = conn()
    ledger.insert_event(c, "2026-01-01T00:00:00+00:00", "sess-001", "transfer",
                         "acct-1", 100, "DENY", scope_id="agent-a")
    ledger.insert_override(c, "2026-01-01T00:05:00+00:00", "agent-a",
                            "sid", "manual review, approved")
    c.commit()
    assert breaker.is_tripped(c, "agent-a") is False


def test_override_before_the_deny_does_not_count():
    c = conn()
    ledger.insert_override(c, "2026-01-01T00:00:00+00:00", "agent-a",
                            "sid", "unrelated earlier approval")
    ledger.insert_event(c, "2026-01-01T00:05:00+00:00", "sess-001", "transfer",
                         "acct-1", 100, "DENY", scope_id="agent-a")
    c.commit()
    assert breaker.is_tripped(c, "agent-a") is True


def test_deny_in_a_nested_task_trips_the_home():
    c = conn()
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 100,
                         "DENY", scope_id="agent-a/task-x")
    c.commit()
    assert breaker.is_tripped(c, "agent-a") is True


def test_scope_is_not_tripped_by_another_scopes_deny():
    c = conn()
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 100,
                         "DENY", scope_id="agent-b")
    c.commit()
    assert breaker.is_tripped(c, "agent-a") is False
