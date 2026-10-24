import { AlertTriangle, ArrowUpRight, CheckCircle2 } from 'lucide-react';
import { asPercent, explanationForEvent, money } from '../format.js';

export default function SpendingProgress({ summary, limits }) {
  const { spent, allowed, stopped } = summary;
  const limit = limits.day;
  const remaining = Math.max(0, limit - spent);
  const preview = [...stopped].reverse().find((e) => spent + e.amount_cents > limit) || stopped.at(-1);
  const projected = preview ? spent + preview.amount_cents : spent;
  const previewScale = Math.max(projected, limit);
  const previewCrossesLimit = projected > limit;

  return (
    <section className="panel hero" aria-label="Daily spending limit">
      <div className="hero-top">
        <div>
          <div className="eyebrow"><CheckCircle2 size={16} /> Family spending overview</div>
          <h2>Mom's spending, last 24 hours</h2>
          <p className="muted">Every agent and payment method counts toward one running total.</p>
        </div>
        <div className="limit-pill">24-hour limit · {money(limit)}</div>
      </div>

      <div className="hero-totals">
        <div>
          <div className="hero-amount">{money(spent)} <span>/ {money(limit)}</span></div>
          <div className="muted small">Spent in the last 24 hours</div>
        </div>
        <div className="remaining">
          <div className="remaining-value">{money(remaining)}</div>
          <div className="muted small">Left under the 24-hour limit</div>
        </div>
      </div>

      <div className="spend-track" role="progressbar" aria-label="Actual spending" aria-valuenow={spent} aria-valuemin={0} aria-valuemax={limit}>
        {allowed.filter((event) => !event.known_bill).map((event, i) => (
          <div key={event.event_id} className={`spend-segment seg-tone-${i % 4}`}
            style={{ width: `${asPercent(event.amount_cents, limit)}%` }}
            title={`${event.payee}: ${money(event.amount_cents)} actually spent`} />
        ))}
      </div>
      <div className="range-labels"><span>$0</span><span>{money(limit)} limit</span></div>

      {preview && (
        <div className="attempt-panel">
          <div className="attempt-heading">
            <div className="attempt-heading-icon"><AlertTriangle size={17}/></div>
            <div>
              <strong>What the latest risky payment would have done</strong>
              <p>{explanationForEvent(preview)}</p>
            </div>
          </div>
          <div className="projection-stats">
            <span>Current {money(spent)} <span className="operator">+</span> attempted {money(preview.amount_cents)}</span>
            <strong>{money(projected)} <ArrowUpRight size={15}/></strong>
          </div>
          <div className="projection-track" aria-label="Illustrative projection, no rejected money spent">
            <div className="projection-actual" style={{ width: `${asPercent(spent, previewScale)}%` }}/>
            <div className="projection-ghost" style={{ left: `${asPercent(spent, previewScale)}%`, width: `${asPercent(preview.amount_cents, previewScale)}%` }}/>
            <div className="projection-cap" style={{ left: `${asPercent(limit, previewScale)}%` }}/>
          </div>
          <div className="projection-footer">
            <span><span className="ghost-key"/> Outlined = attempted, not spent</span>
            <span>{previewCrossesLimit ? 'This attempt also crosses the standard daily limit' : 'This request was blocked by another spending rule'}</span>
          </div>
        </div>
      )}
      <p className="policy-note">The displayed $500 is the standard policy limit. Security alerts can trigger stricter limits; only the guard authorizes payments.</p>
    </section>
  );
}
