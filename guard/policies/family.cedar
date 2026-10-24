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

// Daily total: $500, $100 after a scam flag. A known bill within its usual
// amount is exempt (bill_increase covers it) but still counts toward the
// total, so it shows on the running-total bar.
@id("daily_cap")
forbid (principal, action == Action::"pay", resource)
when {
    !context.known_bill &&
    context.day_total >
        (if context.tainted then context.limits.day_flagged else context.limits.day)
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
