"""The glue between the append-only ledger and Cedar.

Cedar stays exactly as stateless as it's designed to be: it only ever sees a
`cumulative_cost` number that already includes the pending action. All the
"memory" lives in ledger.py / aggregates.py — never inside a policy.

The check (read the running total) and the act (log this attempt) happen
inside one SQLite transaction opened with BEGIN IMMEDIATE, so two concurrent
requests can't both read the same stale total and both get approved. That
race — not Cedar's statelessness itself — is the actual loophole this file
exists to close. See PRIMER.md §1.4.
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import aggregates, breaker, ledger

POLICY_PATH = Path(__file__).parent / "policies" / "budget.cedar"

# Spending older than this no longer counts toward the budget. Rolling, not
# calendar: with a midnight reset, a full budget at 11:59 PM and another at
# 12:01 AM would both fit. Without any window, a home that spent its budget
# once was locked out forever.
BUDGET_WINDOW = timedelta(hours=24)

# The Cedar CLI to run. Overridable so a demo or a test can point it at a
# binary that hangs or is missing and show the guard failing closed.
CEDAR_BIN = os.environ.get("ACCRUE_CEDAR_BIN", "cedar")

# A clean Cedar call takes a few milliseconds. The call runs while
# authorize_transfer holds the ledger's write lock, so a hung Cedar with no
# timeout blocked every other request until it got "database is locked".
CEDAR_TIMEOUT_SECONDS = 2.0

# $10 billion. Anything bigger is a bug or an attack, and the running total
# has to stay well inside Cedar's 64-bit Long.
MAX_AMOUNT_CENTS = 10**12


def _entity_uid(entity_type, entity_id):
    """Build a Cedar entity UID like Account::"acct-1234" from an
    untrusted id.

    The id sits inside a Cedar string literal, so a raw `"` or `\\` in it
    would end the literal early or start an escape - `x" ...` stops being one
    id. Today that only makes the request fail to parse, because no policy
    reads principal or resource, but it would become a bypass the moment one
    does. Quotes and backslashes are escaped; control characters, which
    Cedar won't accept in an id at all, are rejected as malformed input.
    """
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in entity_id):
        raise ValueError(
            f"{entity_type} id must not contain control characters, got {entity_id!r}"
        )
    escaped = entity_id.replace("\\", "\\\\").replace('"', '\\"')
    return f'{entity_type}::"{escaped}"'


def _ask_cedar(principal, action, resource, context, policy_path=None):
    """Shell out to the `cedar` CLI and return "ALLOW" or "DENY", under
    `policy_path` (default: POLICY_PATH). See _run_cedar."""
    decision, _ = _run_cedar(principal, action, resource, context, policy_path)
    return decision


# What `cedar authorize -v` prints between the decision and the ids of the
# policies that decided it.
_CEDAR_REASONS_HEADER = "note: this decision was due to the following policies:"


def _run_cedar(principal, action, resource, context, policy_path=None,
               schema_path=None, verbose=False):
    """Shell out to the `cedar` CLI. Returns (decision, policy_ids):
    "ALLOW" or "DENY", and - with `verbose` - the ids of the policies that
    decided it (each policy's @id). Without `verbose` the ids are [].

    With `schema_path`, Cedar checks the request against the schema before
    evaluating it, so a context with a missing or misspelled attribute is
    rejected outright instead of reaching a policy.

    Cedar does not abort when a policy errors while being evaluated (e.g. a
    context attribute typo'd in a `when` clause, or a request built with a
    different context shape than the policy expects). It drops just that
    policy and keeps going with whatever's left - so a `forbid` that
    references a bad attribute can be silently skipped and a `permit`
    elsewhere wins by default. The CLI still exits 0 for that case; the only
    sign anything went wrong is extra text on stdout after the decision
    word. A clean answer is *only* "ALLOW" or "DENY", plus with `verbose`
    the reasons header and a list of policy ids - anything else means a
    policy errored and the decision can't be trusted, so this raises
    instead of returning it. `cedar validate` (run in CI against
    budget.cedarschema) is what's supposed to catch these before they ship;
    this check is the last line of defense if one gets through anyway.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        context_path = Path(tmpdir) / "context.json"
        entities_path = Path(tmpdir) / "entities.json"
        context_path.write_text(json.dumps(context))
        entities_path.write_text("[]")

        command = [
            CEDAR_BIN,
            "authorize",
            "--policies", str(policy_path or POLICY_PATH),
            "--entities", str(entities_path),
            "--principal", principal,
            "--action", action,
            "--resource", resource,
            "--context", str(context_path),
        ]
        if schema_path is not None:
            command += ["--schema", str(schema_path)]
        if verbose:
            command.append("--verbose")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=CEDAR_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            # run() has already killed the process. Raising rolls back
            # authorize_transfer's transaction and releases the lock;
            # nothing is logged and nothing is allowed.
            raise RuntimeError(
                f"cedar authorize timed out after {CEDAR_TIMEOUT_SECONDS}s"
            ) from None
        # The CLI exits 0 for ALLOW and 2 for DENY - both are real decisions.
        # Anything else (bad policy file, malformed context, ...) is a tool
        # failure and must not be silently treated as a DENY decision.
        if result.returncode not in (0, 2):
            # The CLI prints most failures to stdout, not stderr.
            raise RuntimeError(
                f"cedar authorize failed: {(result.stderr or result.stdout).strip()}"
            )

        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        decision, rest = (lines[0], lines[1:]) if lines else ("", [])
        policy_ids = []
        if verbose and rest and rest[0] == _CEDAR_REASONS_HEADER:
            policy_ids = rest[1:]
            rest = [] if all(_is_policy_id(p) for p in policy_ids) else rest
        if decision not in ("ALLOW", "DENY") or rest:
            raise RuntimeError(
                "cedar authorize returned more than a clean decision - a "
                "policy likely errored while evaluating and was silently "
                f"dropped, so this can't be trusted: {result.stdout.strip()!r}"
            )
        return decision, policy_ids


def _is_policy_id(text):
    """A bare @id like "daily_cap" - not an error message that happened to
    land in the list."""
    return text.replace("_", "").replace("-", "").isalnum()


def authorize_transfer(conn, session_id, resource, amount_cents, scope_id=None,
                       request_id=None, policy_path=None):
    """Ask "can this transfer happen?", accounting for everything this
    scope has already spent - across every session under it, not just this
    one. Returns "ALLOW" or "DENY" and logs the attempt either way — only
    ALLOWed amounts count toward future totals.

    `scope_id` is the durable cross-session identity to check and log this
    event under (see aggregates.cumulative_cost_for_scope - it rolls up a
    flat scope_id or a filesystem-shaped path the same way). Defaults to
    session_id, so a caller with no separate scope concept yet behaves
    exactly as before - a lone session is just a scope of one. A session_id
    containing "/" can't be used that way (see below), so pass scope_id
    explicitly for those.

    The budget covers what the home spent in the last BUDGET_WINDOW. The
    breaker has no window: once tripped, it stays tripped until an override.

    The budget and the breaker are enforced at the scope's *home* - its
    first path segment - not at the full path: "agent-a/task-x" and
    "agent-a/task-y" share one budget, and a DENY in either trips both.
    The event itself is still logged under the full path. This assumes the
    integrator, not the agent, sets the home segment; an agent that can
    choose its own home can still get a fresh budget per home.

    `amount_cents` must be a non-negative int, at most MAX_AMOUNT_CENTS.
    Money is integer cents everywhere (CLAUDE.md), so a float, a bool or a
    string is malformed input, not a decision: it raises rather than
    returning DENY, and nothing is logged. A negative amount would be
    ALLOWed (it only lowers prospective_total) and then logged as an ALLOW
    row that subtracts from every future total - a -$50,000 "transfer"
    buys $50,000 of extra headroom.

    `request_id` makes a retry safe. If an event with this request_id is
    already in the ledger, its decision is returned and nothing new is
    logged, so an agent that times out and asks again isn't counted (or
    paid) twice. Reusing a request_id for a different request raises.

    `policy_path` is the Cedar policy to decide under (default:
    POLICY_PATH), so a draft policy can be checked beside the live one.
    """
    # type() rather than isinstance(): bool is a subclass of int, and True
    # is not one cent.
    if type(amount_cents) is not int or not 0 <= amount_cents <= MAX_AMOUNT_CENTS:
        raise ValueError(
            "amount_cents must be an int between 0 and "
            f"{MAX_AMOUNT_CENTS}, got {amount_cents!r}"
        )
    if request_id is not None and (type(request_id) is not str or not request_id):
        raise ValueError(f"request_id must be a non-empty string, got {request_id!r}")

    # Built before the transaction opens, so a malformed id raises without
    # logging anything - same as a bad amount.
    principal = _entity_uid("Session", session_id)
    account = _entity_uid("Account", resource)

    if not scope_id:
        # A session_id is opaque - nothing says its "/" means a path. Used as
        # a scope, "user/123" would get home "user" and silently share one
        # budget and breaker with "user/456". Refuse instead of guessing.
        if "/" in session_id:
            raise ValueError(
                f"session_id {session_id!r} contains '/', so it can't double as "
                "a scope_id - pass scope_id explicitly"
            )
        scope_id = session_id
    home = aggregates.home_scope(scope_id)
    if not home:
        # "/x" has an empty home, which would roll up to the root - every
        # agent's spend counted against this one request.
        raise ValueError(f"scope_id must start with a home segment, got {scope_id!r}")

    conn.execute("BEGIN IMMEDIATE")
    try:
        # Checked inside the lock, so two copies of one request racing each
        # other can't both miss the first one's row.
        if request_id is not None:
            prior = ledger.find_by_request_id(conn, request_id)
            if prior is not None:
                _, p_session, p_scope, p_resource, p_amount, p_decision = prior
                if (p_session, p_scope, p_resource, p_amount) != (
                    session_id, ledger.normalize_scope(scope_id), resource, amount_cents
                ):
                    raise ValueError(
                        f"request_id {request_id!r} was already used for a "
                        "different request"
                    )
                conn.rollback()
                return p_decision

        now = datetime.now(timezone.utc)
        timestamp = ledger.utc_timestamp(now)

        # A tripped home doesn't get to ask again, no matter how small the
        # amount, how much cumulative-cost headroom remains, or which task
        # under it is asking - that's the whole point of the breaker (see
        # guard/breaker.py). Only an explicit ledger.insert_override logged
        # against the home resets it.
        if breaker.is_tripped(conn, home):
            ledger.insert_event(
                conn, timestamp, session_id, "transfer", resource, amount_cents,
                "DENY", scope_id=scope_id, request_id=request_id,
            )
            conn.commit()
            return "DENY"

        already_spent = aggregates.cumulative_cost_for_scope(
            conn, home, since=ledger.utc_timestamp(now - BUDGET_WINDOW)
        )

        # Integer cents in, integer cents to Cedar: its JSON has only Long
        # integers, so there's no rounding left to get wrong.
        decision = _ask_cedar(
            principal,
            'Action::"transfer"',
            account,
            {"cumulative_cost": already_spent + amount_cents},
            policy_path=policy_path,
        )

        ledger.insert_event(
            conn, timestamp, session_id, "transfer", resource, amount_cents,
            decision, scope_id=scope_id, request_id=request_id,
        )
        conn.commit()
        return decision
    except Exception:
        conn.rollback()
        raise


# --- Family payments ------------------------------------------------------
#
# The guard in front of Mom's money (CLAUDE.md). authorize_transfer above is
# the original accrue check - one cumulative cap - and stays as it was.
# authorize_payment applies the family's spending rules in family.cedar and
# can answer allow, deny or hold. A hold waits for the family: resolve()
# approves or denies it by appending a row. The assumptions behind the
# outcomes are posted on issue #1.

FAMILY_POLICY_PATH = Path(__file__).parent / "policies" / "family.cedar"
FAMILY_SCHEMA_PATH = Path(__file__).parent / "policies" / "family.cedarschema"

# CLAUDE.md's spending rules, in cents, both columns: the normal limit and
# the stricter one after a scam flag. family.cedar picks the column; these
# are handed to it as context, and are what GET /limits should serve.
FAMILY_LIMITS = {
    "day": 50_000,
    "day_flagged": 10_000,
    "gift_card_day": 10_000,
    "new_payee_first": 20_000,
    "recent_payees": 50_000,
    "recent_payees_flagged": 0,
    "breaker_denials": 3,
    "breaker_denials_flagged": 1,
}

# What each forbid in family.cedar does when it fires, in the order a rule
# is reported when several fire: a deny beats a hold, and within each the
# most specific rule comes first, so a $450 gift card on a busy day is
# "gift_card_daily_cap", not just "daily_cap". A rule missing from here is
# treated as a deny, so adding one to the policy can't fail open
# (tests/test_family.py checks the two stay in step).
RULE_OUTCOMES = {
    "delegation_tool": "deny",
    "delegation_budget": "deny",
    "gift_card_daily_cap": "deny",
    "new_payee_cap": "deny",
    "daily_cap": "deny",
    "breaker": "hold",
    "gift_card_needs_approval": "hold",
    "new_payee_needs_approval": "hold",
    "recent_payee_cap": "hold",
    "bill_increase": "hold",
    "daily_cap_needs_approval": "hold",
}

# Cedar failed, crashed or timed out. Fail closed: the payment waits.
GUARD_UNAVAILABLE = "guard_unavailable"

# Which categories each tool can pay. The agent sends the category, so it
# can't be trusted on its own: "pay_bill" labelled "groceries" must not be
# a way to buy gift cards past their cap. The tool is what the guard
# actually does with the money, so it decides. "bill" is accepted for a
# bill of unknown kind, but only "utility" and "rent" can be known bills.
TOOL_CATEGORIES = {
    "pay_bill": {"bill", "utility", "rent", "insurance", "groceries", "pharmacy",
                 "medical", "home_repair", "donation", "subscription", "personal"},
    "buy_gift_card": {"gift_card"},
    "send_zelle": {"transfer"},
    "send_wire": {"transfer"},
    "send_crypto": {"crypto"},
}

BREAKER_WINDOW = timedelta(minutes=10)
KNOWN_BILL_CATEGORIES = {"utility", "rent"}
KNOWN_BILL_LOOKBACK = timedelta(days=45)
RECENT_PAYEE_WINDOW = timedelta(days=30)


def _clean_name(field, value):
    """A required name - person, payee, category, tool, chain link - as the
    lowercase string the ledger stores. Control characters are refused
    (see _entity_uid); "/" is refused because chain links become a scope
    path."""
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field} must be a non-empty string, got {value!r}")
    if "/" in value:
        raise ValueError(f"{field} must not contain '/', got {value!r}")
    _entity_uid(field, value)
    return value.strip().lower()


def _response(event_id, decision, rule, context):
    """CLAUDE.md's /authorize response, rebuilt from what was logged."""
    tainted = context["tainted"]
    limits = context["limits"]
    return {
        "decision": decision.lower(),
        "rule": rule,
        "totals": {"day": context["day_total"],
                   "gift_card_day": context["gift_card_day_total"],
                   "recent_payees": context.get("recent_payees_total", 0)},
        "limits": {"day": limits["day_flagged" if tainted else "day"],
                   "gift_card_day": 0 if tainted else limits["gift_card_day"],
                   "new_payee_first": 0 if tainted else limits["new_payee_first"],
                   "recent_payees": limits.get(
                       "recent_payees_flagged" if tainted else "recent_payees", 0)},
        "needs_approval": decision == "HOLD",
        "event_id": event_id,
    }


def _decide(context, policy_path, outcomes=None):
    """Ask Cedar about one payment. Returns ("ALLOW" | "DENY" | "HOLD", rule).
    Anything that stops Cedar from answering cleanly is a HOLD. `outcomes`
    replaces RULE_OUTCOMES (guard/replay.py passes a draft's)."""
    outcomes = RULE_OUTCOMES if outcomes is None else outcomes
    try:
        decision, fired = _run_cedar(
            _entity_uid("Person", context["person"]),
            'Action::"pay"',
            _entity_uid("Payee", context["payee"]),
            {k: v for k, v in context.items() if k not in ("person", "payee")},
            policy_path=policy_path or FAMILY_POLICY_PATH,
            schema_path=FAMILY_SCHEMA_PATH,
            verbose=True,
        )
    except (RuntimeError, OSError):
        return "HOLD", GUARD_UNAVAILABLE
    if decision == "ALLOW":
        return "ALLOW", None

    order = list(outcomes)
    fired = sorted(fired, key=lambda r: order.index(r) if r in order else -1)
    denies = [r for r in fired if outcomes.get(r, "deny") == "deny"]
    if denies:
        return "DENY", denies[0]
    if fired:
        return "HOLD", fired[0]
    return "DENY", "unknown"


def authorize_payment(conn, *, person, chain, tool, amount_cents, payee, category,
                      session_id, request_id=None, reason=None, tainted=False,
                      policy_path=None, now=None, delegation=None):
    """Ask "can Mom's agent make this payment?" under the family's spending
    rules, log the answer, and return CLAUDE.md's /authorize response:
    decision ("allow", "deny" or "hold"), the rule that decided it, the
    totals including this payment, the limits that applied,
    needs_approval, and the event_id.

    `person` is whose money it is and must be the first link of `chain`,
    the agents asking on their behalf ("mom" / "bills-agent" / ...). The
    budget and breaker are the person's; the event is logged under the
    whole chain. `tainted` is true while the session has seen untrusted
    text or an AI scam label: it switches every rule to the stricter column.
    `request_id` makes retries safe, as in authorize_transfer.

    Fail closed: if Cedar fails, crashes or times out, the payment is logged
    as a hold (rule "guard_unavailable") rather than raising, so it waits
    for the family. A database error still raises, and the caller must treat
    that as a hold too. Malformed input raises ValueError and logs nothing.

    `now` (a timezone-aware datetime) replaces the clock, for replaying a
    simulated month (guard/sim.py). The API never passes it.

    `delegation` is a verified token (guard.tokens.Delegation). With one,
    the chain is the token's - the request's own chain must match it - and
    the token's tools and branch budgets are enforced: each budget is what
    that branch of the chain may spend in 24 hours, and the tightest left
    applies (delegation_budget, delegation_tool).
    """
    if type(amount_cents) is not int or not 0 <= amount_cents <= MAX_AMOUNT_CENTS:
        raise ValueError(
            "amount_cents must be an int between 0 and "
            f"{MAX_AMOUNT_CENTS}, got {amount_cents!r}"
        )
    if type(tainted) is not bool:
        raise ValueError(f"tainted must be a bool, got {tainted!r}")
    if request_id is not None and (type(request_id) is not str or not request_id):
        raise ValueError(f"request_id must be a non-empty string, got {request_id!r}")
    person = _clean_name("person", person)
    if not isinstance(chain, (list, tuple)) or not chain:
        raise ValueError(f"chain must be a non-empty list, got {chain!r}")
    chain = [_clean_name("chain link", link) for link in chain]
    if chain[0] != person:
        raise ValueError(
            f"chain must start with the person paying ({person!r}), got {chain!r}"
        )
    if delegation is not None and tuple(chain) != delegation.chain:
        raise ValueError(
            f"the token was issued to {'/'.join(delegation.chain)!r}, not {'/'.join(chain)!r}"
        )
    payee = _clean_name("payee", payee)
    category = _clean_name("category", category)
    tool = _clean_name("tool", tool)
    if tool not in TOOL_CATEGORIES:
        raise ValueError(f"unknown tool {tool!r}")
    if category not in TOOL_CATEGORIES[tool]:
        raise ValueError(f"{tool} can't pay category {category!r}")
    _entity_uid("session_id", session_id)
    scope_id = "/".join(chain)

    conn.execute("BEGIN IMMEDIATE")
    try:
        if request_id is not None:
            prior = ledger.find_by_request_id(conn, request_id)
            if prior is not None:
                event = ledger.get_event(conn, prior[0])
                if (event["scope_id"], event["payee"], event["amount_cents"]) != (
                    scope_id, payee, amount_cents
                ):
                    raise ValueError(
                        f"request_id {request_id!r} was already used for a "
                        "different request"
                    )
                conn.rollback()
                return _response(event["id"], event["decision"], event["rule"],
                                 event["context"])

        now = now or datetime.now(timezone.utc)
        day_since = ledger.utc_timestamp(now - BUDGET_WINDOW)
        recent_since = ledger.utc_timestamp(now - RECENT_PAYEE_WINDOW)
        is_gift_card = category == "gift_card"
        last_bill = None
        if category in KNOWN_BILL_CATEGORIES:
            last_bill = aggregates.last_payment(
                conn, person, payee, ledger.utc_timestamp(now - KNOWN_BILL_LOOKBACK)
            )
        known_bill = last_bill is not None
        headroom = MAX_AMOUNT_CENTS
        for depth, budget in (delegation.budgets if delegation else ()):
            branch = "/".join(chain[:depth + 1])
            spent = aggregates.cumulative_cost_for_scope(conn, branch, since=day_since)
            headroom = min(headroom, max(budget - spent, 0))
        tools = sorted(TOOL_CATEGORIES if delegation is None or delegation.tools is None
                       else delegation.tools)
        first = aggregates.first_paid(conn, person, payee)
        new_payee = first is None
        recent_payee = not new_payee and first >= recent_since
        context = {
            "person": person,
            "payee": payee,
            "amount": amount_cents,
            "tool": tool,
            "is_gift_card": is_gift_card,
            "tainted": tainted,
            # Known bills and family-approved payments are left out of the
            # day (see aggregates.day_total_for_limit); this one too, if
            # it's a known bill.
            "day_total": aggregates.day_total_for_limit(conn, person, day_since)
                + (0 if known_bill else amount_cents),
            "gift_card_day_total": aggregates.cumulative_cost_for_scope(
                conn, person, since=day_since, category="gift_card")
                + (amount_cents if is_gift_card else 0),
            "new_payee": new_payee,
            "recent_payee": recent_payee,
            "recent_payees_total": aggregates.recent_payees_total(conn, person, recent_since)
                + (amount_cents if new_payee or recent_payee else 0),
            "known_bill": known_bill,
            "last_bill": last_bill or 0,
            "recent_denials": aggregates.denials_since(
                conn, person, ledger.utc_timestamp(now - BREAKER_WINDOW)),
            "delegated_tools": tools,
            "delegation_headroom": headroom,
            "limits": FAMILY_LIMITS,
        }
        decision, rule = _decide(context, policy_path)

        event_id = ledger.insert_event(
            conn, ledger.utc_timestamp(now), session_id, "pay", payee,
            amount_cents, decision, scope_id=scope_id, request_id=request_id,
            payee=payee, category=category, tool=tool, chain=chain,
            reason=reason, rule=rule, context=context,
        )
        conn.commit()
        return _response(event_id, decision, rule, context)
    except Exception:
        conn.rollback()
        raise


def resolve(conn, event_id, action, authorized_by, now=None):
    """The family settles a held payment: `action` is "approve" or "deny".
    Appends a row that resolves the held one and returns its event_id; the
    held row never changes. An approval counts toward the totals from now,
    and goes through even past a limit - the family is the override. Only a
    hold can be resolved, and only once.

    This is POST /override's job. The agent must never be able to call it.
    `now` replaces the clock, as in authorize_payment.
    """
    if action not in ("approve", "deny"):
        raise ValueError(f"action must be 'approve' or 'deny', got {action!r}")
    if type(authorized_by) is not str or not authorized_by.strip():
        raise ValueError(f"authorized_by must be a non-empty string, got {authorized_by!r}")

    conn.execute("BEGIN IMMEDIATE")
    try:
        held = ledger.get_event(conn, event_id)
        if held is None or held["decision"] != "HOLD" or held["resolves"] is not None:
            raise ValueError(f"event {event_id!r} is not a payment waiting for approval")
        if conn.execute("SELECT 1 FROM events WHERE resolves = ?", (event_id,)).fetchone():
            raise ValueError(f"event {event_id!r} was already resolved")

        approved = action == "approve"
        new_id = ledger.insert_event(
            conn, ledger.utc_timestamp(now), held["session_id"], held["action"],
            held["resource"], held["amount_cents"], "ALLOW" if approved else "DENY",
            scope_id=held["scope_id"], resolves=event_id, payee=held["payee"],
            category=held["category"], tool=held["tool"], chain=held["chain"],
            reason=f"{action}d by {authorized_by.strip()}",
            rule="approved_by_family" if approved else "denied_by_family",
        )
        conn.commit()
        return new_id
    except Exception:
        conn.rollback()
        raise
