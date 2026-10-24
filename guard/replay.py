"""Policy replay: what a draft rule would have done to real history.

The plain-English rules screen (plan, Tier 2): the family types a rule,
it's drafted as Cedar, and before it goes live they see "this rule would
have stopped 2 payments last week". Every decision the guard logged keeps
the exact context Cedar was asked about (ledger.SCHEMA), so replay asks
Cedar the same question again under the draft and compares.

It judges each past payment on the facts it had at the time. It doesn't
re-run history forward: had the draft stopped Monday's payment, Tuesday's
totals would have been lower. guard/sim.py is for that.

A draft is a whole policy set (family.cedar with a rule added or changed),
checked against family.cedarschema before anything is replayed. A rule the
guard doesn't know says what it does with an annotation, or it counts as a
deny, as everywhere else:

    @id("no_crypto")
    @outcome("hold")
    forbid (principal, action == Action::"pay", resource)
    when { context.tool == "send_crypto" };
"""

import re
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import authorize, ledger

MAX_ROWS = 5_000  # each row is one Cedar call (a few ms)

# What a context logged before a field existed is missing, filled the way
# the guard behaved then.
_DEFAULTS = {
    "tool": "pay_bill",
    "recent_payee": False,
    "recent_payees_total": 0,
    "delegated_tools": sorted(authorize.TOOL_CATEGORIES),
    "delegation_headroom": authorize.MAX_AMOUNT_CENTS,
}
_ANNOTATIONS = re.compile(r'@id\("([^"]+)"\)\s*@outcome\("(deny|hold)"\)'
                          r'|@outcome\("(deny|hold)"\)\s*@id\("([^"]+)"\)')


class DraftError(ValueError):
    """The draft isn't a valid policy for the guard's schema."""


def outcomes(policy_text):
    """The guard's rule outcomes, plus any the draft declares."""
    found = dict(authorize.RULE_OUTCOMES)
    for a_id, a_out, b_out, b_id in _ANNOTATIONS.findall(policy_text):
        found[a_id or b_id] = a_out or b_out
    return found


def _complete(context):
    context = {**_DEFAULTS, **context, "limits": {
        "recent_payees": authorize.FAMILY_LIMITS["recent_payees"],
        "recent_payees_flagged": authorize.FAMILY_LIMITS["recent_payees_flagged"],
        **context["limits"]}}
    return context


def replay(conn, policy_text, since=None, now=None):
    """Re-decide every payment the guard logged at or after `since` (a
    ledger timestamp; default: the last 7 days before `now`) under
    `policy_text`. Returns {"checked", "changes", "summary"}: `changes`
    lists each payment whose answer would differ, before and after."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "draft.cedar"
        path.write_text(policy_text)
        result = subprocess.run(
            [authorize.CEDAR_BIN, "validate", "--schema", str(authorize.FAMILY_SCHEMA_PATH),
             "--policies", str(path)],
            capture_output=True, text=True, timeout=authorize.CEDAR_TIMEOUT_SECONDS * 5,
        )
        if result.returncode != 0:
            raise DraftError((result.stdout + result.stderr).strip())
        rules = outcomes(policy_text)

        if since is None:
            since = ledger.utc_timestamp((now or datetime.now(timezone.utc)) - timedelta(days=7))
        ids = [i for (i,) in conn.execute(
            "SELECT id FROM events WHERE context IS NOT NULL AND resolves IS NULL "
            "AND timestamp >= ? ORDER BY id LIMIT ?", (since, MAX_ROWS))]
        changes, summary = [], {"newly_stopped": 0, "newly_held": 0, "newly_allowed": 0}
        for event_id in ids:
            event = ledger.get_event(conn, event_id)
            before = (event["decision"], event["rule"])
            after = authorize._decide(_complete(event["context"]), path, rules)
            if after[1] == authorize.GUARD_UNAVAILABLE:
                # Don't report a partial answer as a whole one.
                raise DraftError(f"the rules engine couldn't evaluate event {event_id}")
            if after == before:
                continue
            if before[0] != after[0]:
                key = {"DENY": "newly_stopped", "HOLD": "newly_held", "ALLOW": "newly_allowed"}
                summary[key[after[0]]] += 1
            changes.append({
                "event_id": event_id, "ts": event["timestamp"], "payee": event["payee"],
                "amount_cents": event["amount_cents"], "category": event["category"],
                "before": {"decision": before[0].lower(), "rule": before[1]},
                "after": {"decision": after[0].lower(), "rule": after[1]},
            })
    return {"checked": len(ids), "changes": changes, "summary": summary}
