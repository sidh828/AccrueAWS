import SecurityDemo from './components/SecurityDemo.jsx';
import { useMemo, useState } from 'react';
import { Activity, ArrowRight, CheckCircle2, CircleAlert, CreditCard, LayoutDashboard, LockKeyhole, ShieldCheck, ShieldX, WifiOff } from 'lucide-react';
import { useGuardEvents } from './api.js';
import { money, STANDARD_LIMITS, summarize } from './format.js';
import SpendingProgress from './components/SpendingProgress.jsx';
import ApprovalQueue from './components/ApprovalQueue.jsx';
import ActivityTimeline from './components/ActivityTimeline.jsx';
import CategoryBreakdown from './components/CategoryBreakdown.jsx';

const connectionLabels = {
  connecting: 'Connecting…',
  live: 'Live updates',
  polling: 'Checking for updates',
  offline: 'Dashboard offline',
};

function Sidebar({ view, setView }) {
  return (
    <aside className="sidebar">
      <div className="brand"><div className="brand-icon"><ShieldCheck size={22} strokeWidth={2.2}/></div><div>accrue<span>.</span><small>Family protection</small></div></div>
      <div className="navigation-label">WORKSPACE</div>
      <nav aria-label="Primary navigation">
        <button type="button" className={`nav-item ${view === 'overview' ? 'selected' : ''}`} onClick={() => setView('overview')}><LayoutDashboard size={19}/> Overview</button>
        <button type="button" className={`nav-item ${view === 'activity' ? 'selected' : ''}`} onClick={() => setView('activity')}><Activity size={19}/> Activity</button>
        <button type="button" className={`nav-item ${view === 'demo' ? 'selected' : ''}`} onClick={() => setView('demo')}><ShieldCheck size={19}/> Live Demo</button>
      </nav>
      <div className="navigation-label future-label">COMING NEXT</div>
      <div className="future-item"><CreditCard size={18}/> Spending rules</div>
      <div className="future-item"><LockKeyhole size={18}/> Agent security</div>
      <div className="sidebar-bottom"><ShieldCheck size={19}/><span>Designed to put families<br/>in control of AI spending.</span></div>
    </aside>
  );
}

export default function App() {
  const {events, connection, error, busyId, override, runDemo, demoBusy, canRunDemo, } = useGuardEvents();
  const [view, setView] = useState('overview');
  const [filter, setFilter] = useState('all');
  const summary = useMemo(() => summarize(events), [events]);
  const waitingBreaker = summary.waiting.some((event) => event.rule === 'breaker');
  const nowLabel = new Intl.DateTimeFormat('en-US', { month: 'long', day: 'numeric', year: 'numeric' }).format(new Date());

  return (
    <div className="app-shell">
      <Sidebar view={view} setView={setView}/>
      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">Family dashboard <span>/</span> <strong>{view === 'overview' ? 'Overview' : view === 'demo' ? 'Live Demo' : 'Activity'}</strong></div>
          <div className="topbar-right"><span className="date-label">{nowLabel}</span><div className={`connection-pill ${connection}`}><span className="connection-dot"/>{connectionLabels[connection]}</div></div>
        </header>

        <div className="page-body">
          {error && <div className="error-banner" role="alert"><CircleAlert size={20}/>{error}</div>}
          {connection === 'offline' && <div className="offline-banner" role="status"><WifiOff size={18}/> Dashboard data is unavailable. Payment security is enforced by the guard, not this screen.</div>}
          {waitingBreaker && <div className="breaker-banner" role="alert"><ShieldX size={21}/><div><strong>Recent payment attempts triggered a pause.</strong><span>Review the requests below. The guard decides when further payments are allowed.</span></div></div>}

          {view === 'overview' ? (
            <>
              <div className="page-heading"><div><div className="overline">FAMILY OVERVIEW</div><h1>Protecting what matters.</h1><p>See what Mom's AI assistants spend—and the suspicious requests they cannot complete.</p></div><div className="demo-tag">Accrue · Dashboard</div></div>
              <SpendingProgress summary={summary}/>
              <div className="stats-grid">
                <div className="stat-card"><div className="stat-title"><CheckCircle2 size={17}/> Approved spending</div><strong>{money(summary.spent)}</strong><small>Completed payments today</small></div>
                <div className="stat-card"><div className="stat-title"><ShieldCheck size={17}/> Standard limit remaining</div><strong>{money(Math.max(0, STANDARD_LIMITS.day - summary.spent))}</strong><small>Can be lower during security alerts</small></div>
                <div className="stat-card"><div className="stat-title"><ShieldX size={17}/> Attempts stopped</div><strong>{summary.stoppedAttempts}</strong><small>Denied requests, not dollars saved</small></div>
              </div>
              <div className="dashboard-grid">
                <div className="column-stack">
                  <section className="panel activity-panel"><div className="section-header"><div><div className="section-icon blue-icon"><Activity size={17}/></div><h3>Recent activity</h3></div><button className="text-link" onClick={() => setView('activity')}>View all <ArrowRight size={16}/></button></div><ActivityTimeline events={summary.today}/></section>
                </div>
                <div className="column-stack"><ApprovalQueue waiting={summary.waiting} processing={summary.processing} busyId={busyId} onOverride={override}/><CategoryBreakdown summary={summary}/></div>
              </div>
            </>
          ) : view === 'demo' ? (
            <SecurityDemo
              events={summary.today}
              onRunScenario={runDemo}
              demoBusy={demoBusy}
              canRunDemo={canRunDemo}
            />
          ) : (
            <>
              <div className="page-heading"><div><div className="overline">PAYMENT HISTORY</div><h1>Every request. One clear history.</h1><p>Expand any activity to see why it was allowed, held, or stopped.</p></div></div>
              <section className="panel full-activity"><div className="section-header"><div><div className="section-icon blue-icon"><Activity size={17}/></div><h3>Today's activity <span className="muted count-text">({summary.today.length})</span></h3></div><label className="filter-label">Show <select value={filter} onChange={(e) => setFilter(e.target.value)}><option value="all">All requests</option><option value="allowed">Allowed</option><option value="held">Waiting for you</option><option value="stopped">Stopped</option><option value="pending">Processing</option></select></label></div><ActivityTimeline events={summary.today} full filter={filter}/></section>
            </>
          )}
          <footer className="footer">Accrue protects payments at the guard, not in the browser. <span>Demo frontend · Standard limits shown for illustration.</span></footer>
        </div>
      </main>
    </div>
  );
}
