import test from 'node:test';
import assert from 'node:assert/strict';
import { asPercent, limitsFrom, money, proofFrom, summarize } from './format.js';

test('money uses integer cents and displays two decimal places', () => {
  assert.equal(money(0), '$0.00');
  assert.equal(money(12000), '$120.00');
  assert.equal(money(45005), '$450.05');
  assert.equal(money(-1001), '-$10.01');
  assert.equal(money(12345678), '$123,456.78');
  assert.equal(money(1.25), '—');
});

test('only allowed rows count as actual spending', () => {
  const ts = new Date().toISOString();
  const row = (event_id, status, amount_cents, category='gift_card') => ({ event_id, ts, status, amount_cents, category });
  const result = summarize([row(1,'allowed',5000), row(2,'allowed',12000,'utility'), row(3,'released',45000), row(4,'held',30000), row(5,'pending',500)]);
  assert.equal(result.spent, 17000);
  assert.equal(result.giftCardSpent, 5000);
  assert.equal(result.stoppedAttempts, 1);
  assert.equal(result.waiting.length, 1);
  assert.equal(result.processing.length, 1);
});

test('progress percentages clamp visually without modifying money', () => {
  assert.equal(asPercent(12000,50000), 24);
  assert.equal(asPercent(60000,50000), 100);
});

test('the window is the last 24 hours, like the guard, and known bills are left out', () => {
  const now = Date.parse('2026-10-25T01:00:00Z');
  const at = (hoursAgo) => new Date(now - hoursAgo * 3600_000).toISOString();
  const result = summarize([
    { event_id: 1, ts: at(25), status: 'allowed', amount_cents: 20000, category: 'groceries' },
    { event_id: 2, ts: at(23), status: 'allowed', amount_cents: 10000, category: 'groceries' },
    { event_id: 3, ts: at(2), status: 'allowed', amount_cents: 12000, category: 'utility', known_bill: true },
    { event_id: 4, ts: at(30), status: 'held', amount_cents: 18000, category: 'home_repair' },
  ], now);
  assert.equal(result.spent, 10000);      // 25 hours ago aged out; the known bill doesn't count
  assert.equal(result.knownBills, 12000);
  assert.equal(result.waiting.length, 1);  // held 30 hours ago, still waiting
  assert.equal(result.today.length, 2);
});

test('limits come from GET /limits, with the plan values as a fallback', () => {
  assert.deepEqual(limitsFrom({ normal: { day: 40000, gift_card_day: 5000 } }), { day: 40000, gift_card_day: 5000 });
  assert.deepEqual(limitsFrom(null), { day: 50000, gift_card_day: 10000 });
  assert.deepEqual(limitsFrom({ normal: { day: '1' } }), { day: 50000, gift_card_day: 10000 });
});

test('the proof panel reads /verify in plain words', () => {
  assert.equal(proofFrom(null).state, 'unknown');
  const ok = proofFrom({ ok: true, first_bad_event_id: null, first_bad_override_id: null, head: { event_id: 9, row_hash: 'abcdef0123456789' } });
  assert.equal(ok.state, 'ok');
  assert.equal(ok.fingerprint, 'abcdef012345');
  assert.match(ok.detail, /#9/);
  const broken = proofFrom({ ok: false, first_bad_event_id: 4, first_bad_override_id: null, head: null });
  assert.equal(broken.state, 'broken');
  assert.match(broken.detail, /Payment record #4/);
  assert.match(proofFrom({ ok: false, first_bad_event_id: null, first_bad_override_id: 2 }).detail, /Approval record #2/);
  for (const view of [ok, broken]) assert.doesNotMatch(`${view.title} ${view.detail}`, /ledger|hash|cedar/i);
});
