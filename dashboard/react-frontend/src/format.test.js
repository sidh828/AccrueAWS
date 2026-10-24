import test from 'node:test';
import assert from 'node:assert/strict';
import { asPercent, money, summarize } from './format.js';

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
