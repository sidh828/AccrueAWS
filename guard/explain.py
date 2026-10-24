"""Plain-English explanations of the guard's decisions, for the dashboard
and the phone alerts.

CLAUDE.md: "The AI writes explanations only. Any number that doesn't match
the ledger falls back to a fixed template." So:

- template(event) is the fixed sentence for each rule, filled only with the
  numbers the guard logged for that decision (its context).
- check(text, event) passes a sentence only if every dollar amount and
  every count in it is one of those numbers.
- explain(event, writer=None) asks `writer` - an AI model, any callable
  taking the facts and returning a sentence - and uses its sentence only
  if it passes check(). A writer that fails, invents a number or rounds
  one is replaced by the template. With no writer, it's the template.

The words follow the dashboard's copy rules: plain sentence-case, the
same three states everywhere (allowed, waiting for you, stopped), and
never "Cedar" or "ledger". Explanations are worked out when a row is read
(ledger.contract_rows), not stored, so they never touch the hash chain.
"""

import re

# Counts and spans the templates mention that aren't money.
_FIXED_NUMBERS = {10, 20, 24, 30, 45}


def money(cents):
    return f"${cents / 100:,.2f}"


def facts(event):
    """What an explanation may say about this decision: the payment, its
    decision and rule, and every number the guard logged for it."""
    context = event.get("context") or {}
    limits = context.get("limits") or {}
    tainted = bool(context.get("tainted"))
    return {
        "decision": event["decision"].lower(),
        "rule": event.get("rule"),
        "payee": event.get("payee") or event.get("resource"),
        "amount_cents": event["amount_cents"],
        "tainted": tainted,
        "day_total_cents": context.get("day_total"),
        "day_limit_cents": limits.get("day_flagged" if tainted else "day"),
        "gift_card_day_total_cents": context.get("gift_card_day_total"),
        "gift_card_day_limit_cents": limits.get("gift_card_day"),
        "new_payee_first_limit_cents": limits.get("new_payee_first"),
        "recent_payees_total_cents": context.get("recent_payees_total"),
        "recent_payees_limit_cents": limits.get(
            "recent_payees_flagged" if tainted else "recent_payees"),
        "last_bill_cents": context.get("last_bill") or None,
        "recent_denials": context.get("recent_denials"),
        "breaker_denials": limits.get("breaker_denials_flagged" if tainted
                                      else "breaker_denials"),
        "new_payee": bool(context.get("new_payee")),
        "recent_payee": bool(context.get("recent_payee")),
        "known_bill": bool(context.get("known_bill")),
    }


def template(event):
    """The fixed sentence for this decision."""
    f = facts(event)
    amount, payee, rule = money(f["amount_cents"]), f["payee"], f["rule"]
    scam = " after a suspicious message" if f["tainted"] else ""

    if rule == "approved_by_family":
        return f"Allowed: you approved {amount} to {payee}."
    if rule == "denied_by_family":
        return f"Stopped: you denied {amount} to {payee}."
    if rule == "guard_unavailable":
        return (f"Waiting for you: the safety check couldn't run, so {amount} to {payee} "
                "wasn't paid.")
    if f["decision"] == "allow":
        if f["known_bill"]:
            return f"Allowed: {amount} to {payee}, a regular bill in line with last time."
        if f["new_payee"]:
            return f"Allowed: {amount} to {payee}, the first payment to them."
        if f["recent_payee"]:
            return (f"Allowed: {amount} to {payee}, someone first paid in the last "
                    "30 days.")
        return f"Allowed: {amount} to {payee}."

    sentences = {
        "daily_cap": lambda: (
            f"Stopped: {amount} to {payee} would make {money(f['day_total_cents'])} in "
            f"24 hours. The limit{scam} is {money(f['day_limit_cents'])}."),
        "daily_cap_needs_approval": lambda: (
            f"Waiting for you: {amount} to {payee} would make "
            f"{money(f['day_total_cents'])} in 24 hours, over the "
            f"{money(f['day_limit_cents'])} limit{scam}."),
        "gift_card_daily_cap": lambda: (
            f"Stopped: that would make {money(f['gift_card_day_total_cents'])} in gift "
            f"cards in 24 hours. The limit is {money(f['gift_card_day_limit_cents'])}."),
        "gift_card_needs_approval": lambda: (
            f"Waiting for you: a {amount} gift card{scam or ''} needs your OK."),
        "new_payee_cap": lambda: (
            f"Stopped: {amount} is a first payment to {payee}, and a first payment to "
            f"someone new is limited to {money(f['new_payee_first_limit_cents'])}."),
        "new_payee_needs_approval": lambda: (
            f"Waiting for you: {amount} is a first payment to {payee}{scam}."),
        "recent_payee_cap": lambda: (
            f"Waiting for you: {amount} to {payee} would make "
            f"{money(f['recent_payees_total_cents'])} to people first paid in the last "
            f"30 days. The limit{scam} is {money(f['recent_payees_limit_cents'])}."),
        "bill_increase": lambda: (
            f"Waiting for you: {amount} to {payee} is more than 20% over last time "
            f"({money(f['last_bill_cents'])})."),
        "breaker": lambda: (
            f"Waiting for you: payments are paused after {f['recent_denials']} stopped "
            f"attempts in 10 minutes."),
    }
    if rule in sentences:
        return sentences[rule]()
    state = "Stopped" if f["decision"] == "deny" else "Waiting for you"
    return f"{state}: {amount} to {payee}."


# The facts each rule's sentence is about. A writer's sentence may use only
# these: a number that's real but belongs to something else - the day's
# $500 limit quoted as a gift card total - fails the check too. (It can't
# catch two of the right numbers swapped; the template is what's trusted.)
_RELEVANT = {
    "daily_cap": ("day_total_cents", "day_limit_cents"),
    "daily_cap_needs_approval": ("day_total_cents", "day_limit_cents"),
    "gift_card_daily_cap": ("gift_card_day_total_cents", "gift_card_day_limit_cents"),
    "new_payee_cap": ("new_payee_first_limit_cents",),
    "recent_payee_cap": ("recent_payees_total_cents", "recent_payees_limit_cents"),
    "bill_increase": ("last_bill_cents",),
    "breaker": ("recent_denials", "breaker_denials"),
}

_MONEY = re.compile(r"\$\s?(\d[\d,]*)(?:\.(\d{1,2}))?")
_NUMBER = re.compile(r"(?<![\w.$])(\d+)(?![\d,.])")


def check(text, event):
    """True only if every dollar amount and every bare number in `text` is
    one the guard logged for this decision and that matters to its rule
    (see _RELEVANT), or one of the fixed spans the templates use: 10
    minutes, 20%, 24 hours, 30 days, 45 days."""
    if not isinstance(text, str) or not text.strip() or len(text) > 400:
        return False
    f = facts(event)
    keys = ("amount_cents",) + _RELEVANT.get(f["rule"], ())
    cents = {f[k] for k in keys if k.endswith("_cents") and isinstance(f[k], int)}
    counts = {f[k] for k in keys if not k.endswith("_cents") and isinstance(f[k], int)}
    for whole, fraction in _MONEY.findall(text):
        value = int(whole.replace(",", "")) * 100 + int((fraction or "0").ljust(2, "0"))
        if value not in cents:
            return False
    for number in _NUMBER.findall(_MONEY.sub("", text)):
        if int(number) not in counts | _FIXED_NUMBERS:
            return False
    return True


def explain(event, writer=None):
    """The explanation for one logged decision: the writer's sentence if it
    passes check(), otherwise the template."""
    if writer is not None:
        try:
            text = writer(facts(event))
        except Exception:
            text = None
        if check(text, event):
            return text.strip()
    return template(event)
