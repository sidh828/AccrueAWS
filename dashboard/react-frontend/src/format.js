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

export const STANDARD_LIMITS = Object.freeze({ day: 50000, gift_card_day: 10000 });

export const RULES = Object.freeze({
  gift_card_daily_cap: "Gift card blocked: over today's gift card limit",
  daily_cap: "Blocked: over today's limit",
  new_payee_cap: 'Blocked: first payment to someone new is over the limit',
  known_bill_cap: "Blocked: bill is much higher than last month's",
  breaker: 'Paused: too many blocked attempts in a row',
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

export function isToday(ts) {
  const d = new Date(ts);
  return !Number.isNaN(d.getTime()) && d.toDateString() === new Date().toDateString();
}

export function summarize(events) {
  const today = events.filter((event) => isToday(event.ts));
  const allowed = today.filter((event) => event.status === 'allowed');
  const waiting = today.filter((event) => event.status === 'held');
  const processing = today.filter((event) => event.status === 'pending');
  const stopped = today.filter((event) => event.status === 'released');
  const sum = (list) => list.reduce((n, event) => n + (Number.isSafeInteger(event.amount_cents) ? event.amount_cents : 0), 0);
  return {
    today,
    allowed,
    waiting,
    processing,
    stopped,
    spent: sum(allowed),
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
