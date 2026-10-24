// The family's spending rules (CLAUDE.md, "Spending rules"). Cedar never
// sees the ledger: authorize.authorize_payment hands it this payment's
// totals and the limits, and every rule here is one comparison.
//
// Each forbid has an @id, which is the `rule` the guard reports, and
// authorize.RULE_OUTCOMES says whether that rule denies or holds for the
// family's OK. A deny beats a hold. A rule missing from RULE_OUTCOMES
// denies, so a new rule can't fail open.
//
// "tainted" picks the stricter column: the session saw untrusted text or an
// AI scam label. It only ever makes a rule stricter.

@id("allow_by_default")
permit (principal, action == Action::"pay", resource);

// Daily total: $500, $100 after a scam flag. Known bills (rent, utilities
// within their usual amount) are left out of the total and exempt here -
// bill_increase covers them - so rent day doesn't block groceries.
//
// Over the limit to someone new is a deny: that's what stops a bail or
// "safe account" wire. Over it to someone Margaret has paid before (the
// plumber, her insurer) waits for the family's OK instead, because a deny
// can't be approved.
@id("daily_cap")
forbid (principal, action == Action::"pay", resource)
when {
    !context.known_bill && context.new_payee &&
    context.day_total >
        (if context.tainted then context.limits.day_flagged else context.limits.day)
};

@id("daily_cap_needs_approval")
forbid (principal, action == Action::"pay", resource)
when {
    !context.known_bill && !context.new_payee &&
    context.day_total >
        (if context.tainted then context.limits.day_flagged else context.limits.day)
};

// Recent payees: $500 per 30 days, all together, to payees first paid in the
// last 30 days - so a patient drip to someone she met online, or one spread
// over several new "accounts", waits for the family's OK once it adds up.
// After a scam flag, any payment to a recent payee waits.
@id("recent_payee_cap")
forbid (principal, action == Action::"pay", resource)
when {
    (context.new_payee || context.recent_payee) &&
    context.recent_payees_total >
        (if context.tainted
         then context.limits.recent_payees_flagged
         else context.limits.recent_payees)
};

// Gift cards: $100 a day. After a scam flag, every gift card waits for the
// family's OK.
@id("gift_card_daily_cap")
forbid (principal, action == Action::"pay", resource)
when {
    context.is_gift_card && !context.tainted &&
    context.gift_card_day_total > context.limits.gift_card_day
};

@id("gift_card_needs_approval")
forbid (principal, action == Action::"pay", resource)
when { context.is_gift_card && context.tainted };

// First payment to someone new: $200. After a scam flag, any first payment
// waits for the family's OK.
@id("new_payee_cap")
forbid (principal, action == Action::"pay", resource)
when {
    context.new_payee && !context.tainted &&
    context.amount > context.limits.new_payee_first
};

@id("new_payee_needs_approval")
forbid (principal, action == Action::"pay", resource)
when { context.new_payee && context.tainted };

// Known bills: up to last month's amount plus 20% (amount / last <= 6 / 5).
@id("bill_increase")
forbid (principal, action == Action::"pay", resource)
when { context.known_bill && context.amount * 5 > context.last_bill * 6 };

// Breaker: 3 denials in 10 minutes (1 after a scam flag) and everything
// waits for the family's OK.
@id("breaker")
forbid (principal, action == Action::"pay", resource)
when {
    context.recent_denials >=
        (if context.tainted
         then context.limits.breaker_denials_flagged
         else context.limits.breaker_denials)
};
