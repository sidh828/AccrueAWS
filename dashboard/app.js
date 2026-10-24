// Mom's spending dashboard, plain version: the designer's frames go on top.
// Speaks the API in CLAUDE.md: live rows from GET /stream, falling back to
// polling GET /events?since=<id>, and POST /override for Approve/Deny.
//
// The API is same-origin by default. Add ?api=http://host:port to the page
// URL to use another server (it must allow CORS).

const API = new URLSearchParams(location.search).get("api") || "";

// The guard doesn't send its limits (they aren't in the contract), so these
// copy the normal column of the spending rules in CLAUDE.md.
const LIMITS = { day: 50000, gift_card_day: 10000 };

// On screen, say "spending rules" and "running total", never "Cedar" or
// "ledger". Keep RULES in sync with dashboard/alerts.py.
const RULES = {
  gift_card_daily_cap: "Gift card blocked: over today's gift card limit",
  daily_cap: "Blocked: over today's limit",
  new_payee_cap: "Blocked: first payment to someone new is over the limit",
  known_bill_cap: "Blocked: bill is much higher than last month's",
  breaker: "Paused: too many blocked attempts in a row",
};
const TOOLS = { pay_bill: "bill", buy_gift_card: "gift card", send_zelle: "Zelle payment" };
const CATEGORIES = { utility: "Bills", gift_card: "Gift cards", transfer: "Transfers", home_repair: "Home repair" };
const STATES = { allowed: "Allowed", held: "Waiting for you", pending: "Waiting for you", released: "Stopped" };

const rows = new Map(); // event_id -> the latest version of that row
const busy = new Set(); // event_ids with an Approve/Deny in flight
let lastId = 0;

// ---- data ---------------------------------------------------------------

function connect() {
  const stream = new EventSource(`${API}/stream`);
  stream.onopen = () => setLive("Live");
  stream.onmessage = (e) => upsert([JSON.parse(e.data)]);
  stream.onerror = () => {
    // CLOSED means the server has no /stream (yet): poll /events instead.
    // Otherwise the browser is already reconnecting by itself.
    if (stream.readyState === EventSource.CLOSED) poll();
    else setLive("Reconnecting…");
  };
}

async function poll() {
  try {
    const res = await fetch(`${API}/events?since=${lastId}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    upsert(await res.json());
    setLive("Live (checking every second)");
  } catch {
    setLive("Can't connect. Retrying…");
  }
  setTimeout(poll, 1000);
}

function upsert(list) {
  for (const row of list) {
    rows.set(row.event_id, row);
    lastId = Math.max(lastId, row.event_id);
  }
  render();
}

async function override(row, action) {
  busy.add(row.event_id);
  render();
  try {
    const res = await fetch(`${API}/override`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event_id: row.event_id, action }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    // A changed old row doesn't come back through /events?since, so take
    // it from the response when the API returns it.
    const changed = await res.json();
    if (changed && changed.event_id === row.event_id) rows.set(row.event_id, changed);
  } catch (err) {
    alert(`That didn't go through (${err.message}). Please try again.`);
  } finally {
    busy.delete(row.event_id);
    render();
  }
}

// ---- render -------------------------------------------------------------

function money(cents) {
  const rest = cents % 100;
  const dollars = Math.floor(cents / 100).toLocaleString("en-US");
  return `$${dollars}${rest ? "." + String(rest).padStart(2, "0") : ""}`;
}
const total = (list) => list.reduce((sum, r) => sum + r.amount_cents, 0);
const what = (r) => `${money(r.amount_cents)} ${TOOLS[r.tool] || r.tool.replaceAll("_", " ")} to ${r.payee}`;
const why = (r) => RULES[r.rule] || r.explanation || "Stopped by a spending rule";
const who = (r) => r.chain.slice(1).join(" → ") || r.person;
const time = (r) => new Date(r.ts).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });

// Builds DOM with strings as text, never as HTML: payees and explanations
// come from the agent's side and the red team will try markup in them.
function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function setLive(text) {
  document.getElementById("live").textContent = text;
}

function render() {
  const today = new Date().toDateString();
  const day = [...rows.values()]
    .filter((r) => new Date(r.ts).toDateString() === today)
    .sort((a, b) => a.event_id - b.event_id);
  const allowed = day.filter((r) => r.status === "allowed");
  const waiting = day.filter((r) => r.status === "held" || r.status === "pending");
  const stopped = day.filter((r) => r.status === "released");

  const banner = document.getElementById("banner");
  banner.hidden = !waiting.some((r) => r.rule === "breaker");
  banner.textContent = "Payments are paused after repeated blocked attempts. Nothing goes through until you OK it.";

  document.getElementById("headline").textContent =
    `${money(total(allowed))} of ${money(LIMITS.day)} spent today`;
  document.getElementById("sub").textContent = stopped.length
    ? `Stopped ${stopped.length} ${stopped.length === 1 ? "payment" : "payments"} worth ${money(total(stopped))}`
    : "Nothing stopped today";

  renderBar([...allowed, ...waiting, ...stopped]);
  renderNeedsOk(waiting);
  renderMeters(allowed);
  document.getElementById("timeline").replaceChildren(...day.reverse().map(timelineItem));
}

// The hero: each payment is a segment building toward the daily limit.
// Waiting and stopped attempts go after the spent ones, past the line.
function renderBar(segments) {
  const scale = Math.max(LIMITS.day, total(segments));
  const pct = (cents) => `${(100 * cents) / scale}%`;
  const limit = el("div", { id: "limit" }, el("span", {}, `Today's limit ${money(LIMITS.day)}`));
  limit.style.left = pct(LIMITS.day);
  const bars = segments.map((r) => {
    const seg = el("div", { className: `seg ${r.status}`, title: `${what(r)}: ${STATES[r.status]}` });
    seg.style.width = pct(r.amount_cents);
    return seg;
  });
  document.getElementById("bar").replaceChildren(...bars, limit);
}

function renderNeedsOk(waiting) {
  const cards = waiting.map((r) =>
    el("div", { className: "card" },
      el("p", { className: "what" }, what(r)),
      el("p", {}, `${why(r)}. Asked by ${who(r)}.`),
      el("button", { disabled: busy.has(r.event_id), onclick: () => override(r, "approve") }, "Approve"),
      el("button", { disabled: busy.has(r.event_id), onclick: () => override(r, "deny") }, "Deny"),
    ),
  );
  document.getElementById("needs-ok").replaceChildren(
    ...(cards.length ? cards : [el("p", {}, "Nothing needs your OK.")]),
  );
}

function renderMeters(allowed) {
  const byCategory = new Map();
  for (const r of allowed) byCategory.set(r.category, (byCategory.get(r.category) || 0) + r.amount_cents);
  const giftCards = byCategory.get("gift_card") || 0;
  const others = [...byCategory].filter(([category]) => category !== "gift_card");
  document.getElementById("meters").replaceChildren(
    el("p", {},
      `Gift cards: ${money(giftCards)} of ${money(LIMITS.gift_card_day)} `,
      el("meter", { min: 0, max: LIMITS.gift_card_day, value: giftCards }),
    ),
    ...others.map(([category, cents]) =>
      el("p", {}, `${CATEGORIES[category] || category.replaceAll("_", " ")}: ${money(cents)}`),
    ),
  );
}

function timelineItem(r) {
  return el("li", {},
    el("span", { className: "time" }, time(r)), " ",
    el("span", { className: `state ${r.status}` }, STATES[r.status] || r.status), " ",
    what(r),
    r.status === "allowed" ? "" : el("div", { className: "why" }, `${why(r)}. Asked by ${who(r)}.`),
  );
}

render();
connect();
