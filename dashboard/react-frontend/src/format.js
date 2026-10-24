// Monetary amounts throughout the app remain integer cents.
// BigInt is used for the dollars/cents split to avoid floating-point money math.
export function money(value) {
  if (!Number.isSafeInteger(value)) return '—';
  const cents = BigInt(value);
  const negative = cents < 0n;
  const positive = negative ? -cents : cents;
  const dollars = positive / 100n;
  const remainder = positive % 100n;
  return `${negative ? '-' : ''}$${new Intl.NumberFormat('en-US').format(dollars)}.${String(remainder).padStart(2, '0')}`;
}

// Fallback only: the guard serves its real limits at GET /limits.
export const STANDARD_LIMITS = Object.freeze({ day: 50000, gift_card_day: 10000 });

// The guard's normal-column limits from GET /limits, or the fallback.
export function limitsFrom(apiLimits) {
  const normal = apiLimits?.normal;
  const day = Number.isSafeInteger(normal?.day) ? normal.day : STANDARD_LIMITS.day;
  const gift = Number.isSafeInteger(normal?.gift_card_day) ? normal.gift_card_day : STANDARD_LIMITS.gift_card_day;
  return { day, gift_card_day: gift };
}

// Rule names as guard/authorize.py reports them (RULE_OUTCOMES).
export const RULES = Object.freeze({
  daily_cap: 'Blocked: over the 24-hour limit',
  daily_cap_needs_approval: 'Waiting: over the 24-hour limit, needs your OK',
  gift_card_daily_cap: 'Gift card blocked: over the gift card limit',
  gift_card_needs_approval: 'Waiting: gift cards need your OK after a scam warning',
  new_payee_cap: 'Blocked: first payment to someone new is over the limit',
  new_payee_needs_approval: 'Waiting: someone new, needs your OK',
  new_payee_month_cap: 'Waiting: too much to new payees this month',
  recent_payee_cap: 'Waiting: too many new payees recently',
  bill_increase: "Waiting: bill is more than 20% above last month's",
  breaker: 'Paused: too many blocked attempts in a row',
  delegation_tool: "Blocked: this helper isn't allowed to use that payment method",
  delegation_budget: "Blocked: over this helper's budget",
  guard_unavailable: 'Held: the guard could not check this safely',
});

export const TOOLS = Object.freeze({
  pay_bill: 'Bill payment',
  buy_gift_card: 'Gift card purchase',
  send_zelle: 'Zelle transfer',
});

export const CATEGORIES = Object.freeze({
  utility: 'Bills',
  gift_card: 'Gift cards',
  transfer: 'Transfers',
  home_repair: 'Home repair',
});

export function labelForEvent(event) {
  return TOOLS[event.tool] || readable(event.tool || 'Payment');
}

export function readable(code = '') {
  return String(code).replaceAll('_', ' ').replace(/\b\w/g, (x) => x.toUpperCase());
}

export function explanationForEvent(event) {
  return RULES[event.rule] || event.explanation || 'Stopped by a spending rule';
}

export function chainForEvent(event) {
  const chain = Array.isArray(event.chain) ? event.chain : [];
  return chain.slice(1).join(' → ') || event.person || 'Agent';
}

// The guard's budget is a rolling 24 hours (BUDGET_WINDOW), not the calendar day.
export const WINDOW_MS = 24 * 60 * 60 * 1000;

export function isRecent(ts, now = Date.now()) {
  const t = new Date(ts).getTime();
  return !Number.isNaN(t) && now - t < WINDOW_MS;
}

export function summarize(events, now = Date.now()) {
  // `today` keeps its name for the components, but means the last 24 hours.
  const today = events.filter((event) => isRecent(event.ts, now));
  const allowed = today.filter((event) => event.status === 'allowed');
  // A held payment waits for the family however old it is.
  const waiting = events.filter((event) => event.status === 'held');
  const processing = today.filter((event) => event.status === 'pending');
  const stopped = today.filter((event) => event.status === 'released');
  const sum = (list) => list.reduce((n, event) => n + (Number.isSafeInteger(event.amount_cents) ? event.amount_cents : 0), 0);
  return {
    today,
    allowed,
    waiting,
    processing,
    stopped,
    // Known bills (rent, utilities) don't count toward the guard's running total.
    spent: sum(allowed.filter((event) => !event.known_bill)),
    knownBills: sum(allowed.filter((event) => event.known_bill)),
    giftCardSpent: sum(allowed.filter((event) => event.category === 'gift_card')),
    // "Stopped attempted value" isn't money saved; repeated attempts may target the same dollars.
    stoppedAttempts: stopped.length,
  };
}

export function asPercent(numeratorCents, denominatorCents) {
  if (!denominatorCents) return 0;
  // Used only for CSS presentation; it is NOT monetary calculation.
  return Math.max(0, Math.min(100, (numeratorCents / denominatorCents) * 100));
}
