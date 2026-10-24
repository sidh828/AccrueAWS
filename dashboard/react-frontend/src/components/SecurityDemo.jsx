
const SCENARIOS = [
  {
    id: "normal_day",
    title: "Normal spending",
    description: "$120 power bill and $50 birthday gift card",
    icon: "✓",
  },
  {
    id: "gift_card_scam",
    title: "Gift-card scam",
    description: "Two suspicious $450 gift-card purchases",
    icon: "!",
  },
  {
    id: "channel_switch",
    title: "Switch payment methods",
    description: "Attempt Zelle payment and sub-agent purchase",
    icon: "↗",
  },
  {
    id: "held_bill",
    title: "Paused payment",
    description: "A $180 plumber bill requiring approval",
    icon: "◷",
  },
];

import {
  ShieldCheck,
  ShieldX,
  Clock3,
  ArrowRight
} from "lucide-react";

import {
  money,
  STANDARD_LIMITS,
  explanationForEvent
} from "../format.js";

function statusOf(event) {
  if (event.status === "allowed") {
    return { label: "Allowed", type: "allowed" };
  }
  if (event.status === "released") {
    return { label: "Stopped", type: "stopped" };
  }
  if (event.status === "held") {
    return { label: "Waiting for you", type: "held" };
  }
  return { label: "Processing", type: "pending" };
}

export default function SecurityDemo({events = [], onRunScenario, demoBusy, canRunDemo,}) {
  // Compare gift-card requests against a hypothetical
  // checker that only has a $500 per-request limit.
  const allEvents = [...events].sort(
    (a, b) => a.event_id - b.event_id
  );
  const requests = events
    .filter(
      (event) =>
        event.tool === "buy_gift_card" &&
        Number.isSafeInteger(event.amount_cents) &&
        event.amount_cents > 0 &&
        event.amount_cents <= 50000
    )
    .sort((a, b) => a.event_id - b.event_id);

  const sum = (items) =>
    items.reduce((n, item) => n + item.amount_cents, 0);

  const allowed = requests.filter(
    (r) => r.status === "allowed"
  );
  const stopped = requests.filter(
    (r) => r.status === "released"
  );
  const held = requests.filter(
    (r) => r.status === "held"
  );
  const pending = requests.filter(
    (r) => r.status === "pending"
  );

  const traditionalTotal = sum(requests);
  const accruedTotal = sum(allowed);
  const totalApprovedSpending = sum(
    events.filter((r) => r.status === "allowed")
  );

  // Visualization scale only.
  // All actual monetary calculations remain integer cents.
  const scale = Math.max(
    STANDARD_LIMITS.day,
    traditionalTotal
  );

  const widthFor = (cents) =>
    `${(cents / scale) * 100}%`;

  const limitPosition =
    `${(STANDARD_LIMITS.day / scale) * 100}%`;

  return (
    <div className="security-demo">
      <div className="page-heading">
        <div>
          <div className="overline">
            SECURITY DEMONSTRATION
          </div>
          <h1>See Accrue in action.</h1>
          <p>
            One payment can look safe. The full history
            tells a different story.
          </p>
        </div>
      </div>
      <section className="panel scenario-panel">
        <div className="scenario-header">
          <div>
            <div className="overline">INTERACTIVE SIMULATOR</div>
            <h2>Choose an attack scenario</h2>
            <p>
              Launch a simulated payment sequence and watch Accrue respond.
            </p>
          </div>
          <span className="scenario-mode">Scripted demo</span>
        </div>

        <div className="scenario-grid">
          {SCENARIOS.map((scenario) => (
            <button
              key={scenario.id}
              type="button"
              className="scenario-button"
              disabled={!canRunDemo || demoBusy !== null}
              onClick={() => onRunScenario(scenario.id)}
            >
              <span className="scenario-icon">{scenario.icon}</span>
              <strong>{scenario.title}</strong>
              <small>{scenario.description}</small>
              <span className="scenario-action">
                {demoBusy === scenario.id
                  ? "Starting..."
                  : "Run scenario →"}
              </span>
            </button>
          ))}
        </div>

        {!canRunDemo && (
          <p className="scenario-warning">
            Read-only mode. Open the dashboard using its authorized link
            to run simulations.
          </p>
        )}

        <p className="scenario-note">
          Each scenario adds transactions to the current demonstration.
          Restart the Python simulator to clear the history.
          Outcomes are scripted, not calculated by the real guard.
        </p>
      </section>

      <div className="demo-stats">
        <div className="demo-stat">
          <span>Traditional per-payment check</span>
          <strong className="demo-red">
            {money(traditionalTotal)}
          </strong>
          <small>Potentially approved</small>
        </div>

        <div className="demo-stat">
          <span>Total spending approved by Accrue</span>
          <strong className="demo-green">
            {money(totalApprovedSpending)}
          </strong>
          <small>
            Includes {money(accruedTotal)} in gift-card purchases
          </small>
        </div>

        <div className="demo-stat">
          <span>Protection results</span>
          <strong>{stopped.length} stopped</strong>
          <small>
            {held.length} waiting · {pending.length} processing
          </small>
        </div>
      </div>

      <section className="panel demo-comparison">
        <div className="demo-comparison-header">
          <div>
            <div className="overline">SIDE-BY-SIDE COMPARISON</div>
            <h2>Same requests. Different outcomes.</h2>
            <p>
              The traditional checker examines each payment.
              Accrue considers the history and spending rules.
            </p>
          </div>
          <span className="demo-live-label">
            <span className="demo-live-dot" />
            Live transaction data
          </span>
        </div>

        <div className="demo-system">
          <div className="demo-system-heading">
            <div className="demo-system-name">
              <ShieldX size={21} />
              <span>Traditional checker</span>
            </div>
            <strong className="demo-red">
              {money(traditionalTotal)}
            </strong>
          </div>

          <p className="demo-description">
            Every request shown is within the individual
            $500 payment limit.
          </p>

          <div className="demo-track">
            {requests.map((r, index) => (
              <div
                key={r.event_id}
                className="demo-segment traditional"
                style={{
                  width: widthFor(r.amount_cents),
                  animationDelay: `${index * 100}ms`
                }}
                title={`${money(r.amount_cents)} could pass`}
              />
            ))}
            <div
              className="demo-limit-marker"
              style={{ left: limitPosition }}
            />
          </div>

          <div className="demo-track-footer">
            <span>$0</span>
            <span>Dashed line = standard $500 daily cap</span>
            <span>{money(scale)}</span>
          </div>
        </div>

        <div className="demo-divider">
          <ArrowRight size={20} />
          <span>Now add spending history</span>
        </div>

        <div className="demo-system accrue-system">
          <div className="demo-system-heading">
            <div className="demo-system-name">
              <ShieldCheck size={21} />
              <span>Protected by Accrue</span>
            </div>
            <strong className="demo-green">
              {money(accruedTotal)}
            </strong>
          </div>

          <p className="demo-description">
            Only approved payments become completed spending.
            Outlined segments show requests that did not go through.
          </p>

          <div className="demo-track">
            {requests.map((r, index) => {
              const state = statusOf(r);
              return (
                <div
                  key={r.event_id}
                  className={`demo-segment accrue-${state.type}`}
                  style={{
                    width: widthFor(r.amount_cents),
                    animationDelay: `${index * 100}ms`
                  }}
                  title={`${money(r.amount_cents)} — ${state.label}`}
                />
              );
            })}
            <div
              className="demo-limit-marker"
              style={{ left: limitPosition }}
            />
          </div>

          <div className="demo-track-footer">
            <span>$0</span>
            <span>Standard daily cap, for reference</span>
            <span>{money(scale)}</span>
          </div>

          <div className="demo-legend">
            <span><i className="legend-allowed" /> Allowed</span>
            <span><i className="legend-stopped" /> Stopped attempt</span>
            <span><i className="legend-held" /> Waiting / processing</span>
          </div>
        </div>

        <div className="demo-insight">
          <ShieldCheck size={24} />
          <div>
            <strong>
              Spending history changes the outcome.
            </strong>
            <p>
              Under a simple $500 per-request check,
              these requests could all pass.
              Accrue allowed {money(accruedTotal)} and
              stopped {stopped.length} requests.
            </p>
          </div>
        </div>
      </section>

      <section className="panel demo-requests">
        <div className="demo-requests-header">
          <div>
            <h2>Payment-by-payment breakdown</h2>
            <p>
              Follow each request and see how the guard responds.
            </p>
          </div>
          <span>{allEvents.length} requests</span>
        </div>

        {allEvents.length === 0 ? (
          <p className="demo-empty">
            Waiting for the first gift-card request...
          </p>
        ) : (
          <div className="demo-request-list">
            {allEvents.map((r, index) => {
              const state = statusOf(r);

              return (
                <div
                  className="demo-request"
                  key={r.event_id}
                >
                  <div className="demo-request-index">
                    {index + 1}
                  </div>

                  <div className="demo-request-info">
                    <strong>{r.payee}</strong>
                    <span>
                      {r.tool === "pay_bill"
                        ? "Bill payment"
                        : r.tool === "send_zelle"
                        ? "Zelle transfer"
                        : r.tool === "buy_gift_card"
                        ? "Gift-card purchase"
                        : "Payment request"}
                      {(state.type === "stopped" || state.type === "held") &&
                        ` · ${explanationForEvent(r)}`}
                    </span>
                  </div>

                  <div className="demo-request-result">
                    <strong>{money(r.amount_cents)}</strong>
                    <span className={`demo-status ${state.type}`}>
                      {state.type === "allowed" && (
                        <ShieldCheck size={14} />
                      )}
                      {state.type === "stopped" && (
                        <ShieldX size={14} />
                      )}
                      {(state.type === "held" ||
                        state.type === "pending") && (
                        <Clock3 size={14} />
                      )}
                      {state.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <p className="demo-disclaimer">
        This comparison is illustrative. The traditional
        checker assumes only a $500 individual-payment
        limit. Accrue outcomes are read from the guard's
        event history. The standard daily cap shown is not
        necessarily the currently effective security limit.
      </p>
    </div>
  );
}
