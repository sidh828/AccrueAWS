import { Clock3, ShieldAlert } from 'lucide-react';
import { chainForEvent, explanationForEvent, labelForEvent, money } from '../format.js';

export default function ApprovalQueue({ waiting, processing, busyId, onOverride }) {
  return (
    <section className="panel approvals" aria-label="Payments awaiting approval">
      <div className="section-header">
        <div>
          <div className="section-icon warning-icon"><Clock3 size={17}/></div>
          <h3>Needs your OK</h3>
        </div>
        {waiting.length > 0 && <span className="count-pill">{waiting.length}</span>}
      </div>
      {waiting.length === 0 && processing.length === 0 && (
        <div className="empty-state"><ShieldAlert size={24}/><strong>Nothing needs your approval</strong><p>We'll show requests here when an agent needs your decision.</p></div>
      )}
      {waiting.map((event) => (
        <div className="approval-request" key={event.event_id}>
          <div className="approval-details">
            <div className="approval-type">{labelForEvent(event)}</div>
            <div className="approval-amount">{money(event.amount_cents)}</div>
            <div className="approval-payee">To {event.payee}</div>
          </div>
          <div className="approval-reason">{explanationForEvent(event)}<span className="muted small">Requested by {chainForEvent(event)}</span></div>
          <div className="approval-buttons">
            <button type="button" className="btn btn-outline" disabled={busyId !== null}
              onClick={() => onOverride(event, 'deny')}>Deny</button>
            <button type="button" className="btn btn-primary" disabled={busyId !== null}
              onClick={() => {
                if (window.confirm(`Approve ${money(event.amount_cents)} to ${event.payee}? This sends an override to the guard.`)) onOverride(event, 'approve');
              }}>{busyId === event.event_id ? 'Submitting…' : 'Approve'}</button>
          </div>
        </div>
      ))}
      {processing.map((event) => (
        <div className="processing-row" key={event.event_id}>
          <Clock3 size={16}/> {money(event.amount_cents)} to {event.payee} · Processing (not yet available to approve)
        </div>
      ))}
    </section>
  );
}
