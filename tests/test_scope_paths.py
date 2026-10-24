"""Scope paths: a scope_id can be a filesystem-shaped lineage
("agent-a/task-checkout-flow"), and aggregates.cumulative_cost_for_scope
rolls up a node plus everything nested under it - the same prefix trick
`du` uses on a real filesystem. See NOTES.md "Scope paths".
"""

from src import aggregates, ledger


def conn():
    return ledger.connect(":memory:")


def test_home_level_rolls_up_every_task_under_it():
    c = conn()
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 3000,
                         "ALLOW", scope_id="agent-a/task-checkout")
    ledger.insert_event(c, "t2", "sess-002", "transfer", "acct-1", 4000,
                         "ALLOW", scope_id="agent-a/task-refunds")
    c.commit()

    # The home level ("agent-a") sees both of its tasks combined.
    assert aggregates.cumulative_cost_for_scope(c, "agent-a") == 7000


def test_task_level_does_not_see_sibling_tasks():
    c = conn()
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 3000,
                         "ALLOW", scope_id="agent-a/task-checkout")
    ledger.insert_event(c, "t2", "sess-002", "transfer", "acct-1", 4000,
                         "ALLOW", scope_id="agent-a/task-refunds")
    c.commit()

    assert aggregates.cumulative_cost_for_scope(c, "agent-a/task-checkout") == 3000


def test_home_level_also_counts_its_own_direct_events():
    c = conn()
    # an event logged straight at the home level, no task underneath it
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 1000,
                         "ALLOW", scope_id="agent-a")
    ledger.insert_event(c, "t2", "sess-002", "transfer", "acct-1", 500,
                         "ALLOW", scope_id="agent-a/task-checkout")
    c.commit()

    assert aggregates.cumulative_cost_for_scope(c, "agent-a") == 1500


def test_root_level_sees_every_scope():
    c = conn()
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 1000,
                         "ALLOW", scope_id="agent-a/task-checkout")
    ledger.insert_event(c, "t2", "sess-002", "transfer", "acct-1", 2000,
                         "ALLOW", scope_id="agent-b/task-refunds")
    c.commit()

    assert aggregates.cumulative_cost_for_scope(c, "") == 3000


def test_unrelated_agent_is_not_mistaken_for_a_prefix_match():
    c = conn()
    # "agent-a2" starts with the same characters as "agent-a" but is a
    # different agent entirely - a naive LIKE 'agent-a%' would wrongly
    # include it.
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 1000,
                         "ALLOW", scope_id="agent-a")
    ledger.insert_event(c, "t2", "sess-002", "transfer", "acct-1", 9000,
                         "ALLOW", scope_id="agent-a2/task-checkout")
    c.commit()

    assert aggregates.cumulative_cost_for_scope(c, "agent-a") == 1000


def test_like_wildcard_characters_in_a_scope_id_are_escaped():
    c = conn()
    # "a_b" contains a literal underscore - an unescaped LIKE pattern would
    # treat it as "any single character" and wrongly match "aXb/...".
    ledger.insert_event(c, "t1", "sess-001", "transfer", "acct-1", 500,
                         "ALLOW", scope_id="a_b")
    ledger.insert_event(c, "t2", "sess-002", "transfer", "acct-1", 9000,
                         "ALLOW", scope_id="aXb/task-1")
    c.commit()

    assert aggregates.cumulative_cost_for_scope(c, "a_b") == 500
