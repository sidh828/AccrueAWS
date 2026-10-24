import { Fingerprint, ShieldAlert, ShieldCheck } from 'lucide-react';
import { proofFrom } from '../format.js';

// The proof beat for the video: the guard re-checks every record it wrote,
// live. Edit one row by hand and this turns red, naming the row.
export default function ProofPanel({ result, checkedAt }) {
  const view = proofFrom(result);
  const Icon = view.state === 'broken' ? ShieldAlert : ShieldCheck;
  return (
    <section className={`panel proof proof-${view.state}`} aria-label="Record check" aria-live="polite">
      <div className="section-header">
        <div><div className="section-icon blue-icon"><Fingerprint size={17}/></div><h3>Payment record check</h3></div>
      </div>
      <div className="proof-body">
        <div className="proof-status"><Icon size={22}/><strong>{view.title}</strong></div>
        <p>{view.detail}</p>
        {view.fingerprint && <p className="muted small">Latest fingerprint <code>{view.fingerprint}</code></p>}
        {checkedAt && <p className="muted small">Checked {checkedAt.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' })}</p>}
      </div>
    </section>
  );
}
