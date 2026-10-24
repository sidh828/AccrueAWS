import { ArrowDownLeft, CircleCheck, Clock3, ShieldX } from 'lucide-react';
import { chainForEvent, explanationForEvent, labelForEvent, money } from '../format.js';

const STATUS = {
  allowed: { text: 'Allowed', className: 'allowed', Icon: CircleCheck },
  released: { text: 'Stopped', className: 'stopped', Icon: ShieldX },
  held: { text: 'Waiting for you', className: 'waiting', Icon: Clock3 },
  pending: { text: 'Processing', className: 'waiting', Icon: Clock3 },
};

export default function ActivityTimeline({ events, full = false, filter = 'all' }) {
  const visible = [...events]
    .filter((event) => filter === 'all' || (filter === 'stopped' ? event.status === 'released' : event.status === filter))
    .sort((a, b) => b.event_id - a.event_id);
  const shown = full ? visible : visible.slice(0, 5);
  return (
    <div className="activity-list">
      {shown.length === 0 ? <div className="empty-state"><ArrowDownLeft size={24}/><strong>No payments to show yet</strong><p>Start fake_api.py to play the scripted demo.</p></div> : shown.map((event) => {
        const status = STATUS[event.status] || STATUS.pending;
        const Icon = status.Icon;
        return (
          <details className="activity-item" key={event.event_id}>
            <summary>
              <div className={`activity-icon ${status.className}`}><Icon size={19}/></div>
              <div className="activity-main">
                <strong>{event.payee}</strong>
                <span>{labelForEvent(event)} · {new Date(event.ts).toLocaleTimeString([], {hour: 'numeric', minute: '2-digit'})}</span>
              </div>
              <div className="activity-end">
                <strong>{money(event.amount_cents)}</strong>
                <span className={`status-label ${status.className}`}>{status.text}</span>
              </div>
            </summary>
            <div className="activity-detail">
              <p><strong>Why:</strong> {event.status === 'allowed' ? (event.explanation || 'Passed the spending rules.') : explanationForEvent(event)}</p>
              <p><strong>Agent:</strong> {chainForEvent(event)}</p>
              <p><strong>Category:</strong> {event.category?.replaceAll('_',' ') || 'Other'}</p>
            </div>
          </details>
        );
      })}
    </div>
  );
}
