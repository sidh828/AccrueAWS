// Mom's spending dashboard, plain version: the designer's frames go on top.
// Speaks the API in CLAUDE.md: polls GET /events?since=<id> with a role token
// and POSTs approvals or denials with the approver credential.
//
// The API is same-origin by default. Add ?api=http://host:port to the page
// URL to use another server (it must allow CORS).

const API = new URLSearchParams(location.search).get("api") || "";

// The guard doesn't send its limits (they aren't in the contract), so these
// copy the normal column of the spending rules in CLAUDE.md.
// Replaced by the guard's own numbers from GET /limits when it answers.
const LIMITS = { day: 50000, gift_card_day: 10000 };

// The guard counts spending over a rolling 24 hours (BUDGET_WINDOW in
// guard/authorize.py), so the running total here uses the same window.
// A calendar day would disagree with it every night after midnight.
const WINDOW_MS = 24 * 60 * 60 * 1000;

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
const cards = new Map(); // event_id -> its "Needs your OK" card, reused while unchanged
let lastId = 0;
let liveText = "Connecting…";
let broken = false; // the last redraw threw
let drawQueued = false;
let canAct = false;

// Seeing payments and approving both need the dashboard's token. The server prints a link ending in
// #token=...; opening it once on a device lets that device approve. The
// token is kept on the device and taken out of the address bar, so it never
// shows on a shared screen or in the video. Without it the page shows
// nothing. The agent never has it.
const TOKEN_KEY = "accrue-dashboard-token";
const READ_ONLY = "To approve or deny from this screen, open the dashboard link the server printed.";
let token = takeToken();

function takeToken() {
  const fromLink = new URLSearchParams(location.hash.slice(1)).get("token");
  if (fromLink) {
    history.replaceState(null, "", location.pathname + location.search);
    try {
      localStorage.setItem(TOKEN_KEY, fromLink);
    } catch {}
    return fromLink;
  }
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function forgetToken() {
  token = null;
  canAct = false;
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {}
}

// ---- data ---------------------------------------------------------------

async function loadLimits() {
  try {
    const res = await fetch(`${API}/limits`);
    const normal = res.ok ? (await res.json()).normal : null;
    if (normal && Number.isSafeInteger(normal.day)) LIMITS.day = normal.day;
    if (normal && Number.isSafeInteger(normal.gift_card_day)) LIMITS.gift_card_day = normal.gift_card_day;
    draw();
  } catch {} // keep the plan's numbers
}

function connect() {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  fetch(`${API}/whoami`, { headers, cache: "no-store" })
    .then(async (response) => {
      if (response.ok) {
        const identity = await response.json();
        canAct = identity.role === "approver" || identity.role === "admin";
      } else if (response.status === 404) {
        canAct = Boolean(token);
      } else {
        canAct = false;
      }
      draw();
      poll();
    })
    .catch(() => {
      canAct = false;
      poll();
    });
}

async function poll() {
  try {
    const headers = token ? { Authorization: `Bearer ${token}` } : {};
    const res = await fetch(`${API}/events?since=${lastId}`, { headers });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    upsert(await res.json());
    setLive("Live (checking every second)");
  } catch (err) {
    setLive(err.message === "no token"
      ? "To see payments here, open the dashboard link the server printed."
      : "Can't connect. Retrying…");
  }
  setTimeout(poll, 1000);
}

function upsert(list) {
  for (const row of Array.isArray(list) ? list : []) {
    if (!row || !Number.isSafeInteger(row.event_id)) continue; // nothing to key it by
    rows.set(row.event_id, row);
    lastId = Math.max(lastId, row.event_id);
  }
  draw();
}

async function override(row, action) {
  busy.add(row.event_id);
  draw();
  try {
    const res = await fetch(`${API}/override`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ event_id: row.event_id, action }),
    });
    if (res.status === 401) forgetToken(); // a stale or wrong token: back to read-only
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    // A changed old row doesn't come back through /events?since, so take
    // it from the response when the API returns it.
    const changed = await res.json();
    if (changed && changed.event_id === row.event_id) rows.set(row.event_id, changed);
  } catch (err) {
    alert(token ? `That didn't go through (${err.message}). Please try again.` : READ_ONLY);
  } finally {
    busy.delete(row.event_id);
    draw();
  }
}

// ---- render -------------------------------------------------------------

// Rows come from the guard, but tool, payee, category and chain start out as
// whatever the agent asked for. Look names up without reaching the object
// prototype ("constructor", "toString"), and fall back when a field is odd.
const lookup = (table, key) => (typeof key === "string" && Object.hasOwn(table, key) ? table[key] : undefined);
const text = (value, fallback) => (typeof value === "string" && value !== "" ? value : fallback);

function money(cents) {
  if (!Number.isSafeInteger(cents)) return "An unknown amount";
  if (cents < 0) return `-${money(-cents)}`;
  const rest = cents % 100;
  const dollars = Math.floor(cents / 100).toLocaleString("en-US");
  return `$${dollars}${rest ? "." + String(rest).padStart(2, "0") : ""}`;
}
const cents = (r) => (Number.isSafeInteger(r.amount_cents) ? r.amount_cents : 0);
const total = (list) => list.reduce((sum, r) => sum + cents(r), 0);
const toolName = (r) => lookup(TOOLS, r.tool) || text(r.tool, "payment").replaceAll("_", " ");
const what = (r) => `${money(r.amount_cents)} ${toolName(r)} to ${text(r.payee, "an unknown payee")}`;
const why = (r) =>
  lookup(RULES, r.rule) || text(r.explanation, r.status === "held" ? "Waiting for your OK" : "Stopped by a spending rule");
const who = (r) => (Array.isArray(r.chain) ? r.chain.slice(1).map(String).join(" → ") : "") || text(r.person, "the agent");
const state = (r) => (lookup(STATES, r.status) ? r.status : "unknown"); // safe as a class name
const stateLabel = (r) => lookup(STATES, r.status) || "Unknown";

// The last 24 hours reach into yesterday, so a bare "1:43 PM" could be
// either day: anything not from today says which day it was.
function time(r) {
  const when = new Date(r.ts);
  if (Number.isNaN(when.getTime())) return "";
  const clock = when.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  const day = new Date();
  if (when.toDateString() === day.toDateString()) return clock;
  day.setDate(day.getDate() - 1);
  if (when.toDateString() === day.toDateString()) return `Yesterday ${clock}`;
  return `${when.toLocaleDateString([], { weekday: "short" })} ${clock}`;
}

// Builds DOM with strings as text, never as HTML: payees and explanations
// come from the agent's side and the red team will try markup in them.
function el(tag, props = {}, ...children) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

const nothingWaiting = el("p", {}, "Nothing needs your OK.");

function setLive(message) {
  liveText = message;
  showLive();
}

function showLive() {
  document.getElementById("live").textContent = broken
    ? "Couldn't show the latest update. Reload the page."
    : liveText;
}

// Redraw at most once per frame, however fast rows arrive. If a redraw
// throws, say so instead of freezing while still saying "Live".
function draw() {
  if (drawQueued) return;
  drawQueued = true;
  requestAnimationFrame(() => {
    drawQueued = false;
    try {
      render();
      broken = false;
    } catch (err) {
      console.error(err);
      broken = true;
    }
    showLive();
  });
}

function render() {
  const now = Date.now();
  const recent = (r) => now - new Date(r.ts).getTime() < WINDOW_MS; // false for a bad ts
  const all = [...rows.values()].sort((a, b) => a.event_id - b.event_id);
  const last24 = all.filter(recent);
  const allowed = last24.filter((r) => r.status === "allowed");
  // The guard's running total leaves out known bills and family-approved payments.
  const counted = allowed.filter((r) => !r.known_bill && r.resolved_by == null);
  const stopped = last24.filter((r) => r.status === "released");
  // A held payment waits for the family however long that takes, so unlike
  // the running total it isn't limited to the last 24 hours.
  const waiting = all.filter((r) => r.status === "held" || r.status === "pending");

  const banner = document.getElementById("banner");
  banner.hidden = !waiting.some((r) => r.rule === "breaker");
  banner.textContent = "Payments are paused after repeated blocked attempts. Nothing goes through until you OK it.";

  document.getElementById("headline").textContent =
    `${money(total(counted))} of ${money(LIMITS.day)} spent in the last 24 hours`;
  document.getElementById("sub").textContent = stopped.length
    ? `Stopped ${stopped.length} ${stopped.length === 1 ? "payment" : "payments"} worth ${money(total(stopped))}`
    : "Nothing stopped in the last 24 hours";

  renderBar([...counted, ...waiting.filter(recent), ...stopped]);
  renderNeedsOk(waiting);
  renderMeters(allowed);
  document.getElementById("timeline").replaceChildren(...last24.reverse().map(timelineItem));
}

// The hero: each payment is a segment building toward the daily limit.
// Waiting and stopped attempts go after the spent ones, past the line.
function renderBar(segments) {
  const scale = Math.max(LIMITS.day, total(segments));
  const pct = (amount) => `${(100 * amount) / scale}%`;
  const limit = el("div", { id: "limit" }, el("span", {}, `24-hour limit ${money(LIMITS.day)}`));
  limit.style.left = pct(LIMITS.day);
  const bars = segments.map((r) => {
    const seg = el("div", { className: `seg ${state(r)}`, title: `${what(r)}: ${stateLabel(r)}` });
    seg.style.width = pct(cents(r));
    return seg;
  });
  document.getElementById("bar").replaceChildren(...bars, limit);
}

// Cards are the only things people click, so a card is reused while its row
// and button state are unchanged: a click that lands mid-redraw still hits
// the same button.
function renderNeedsOk(waiting) {
  const ids = new Set(waiting.map((r) => r.event_id));
  for (const id of cards.keys()) if (!ids.has(id)) cards.delete(id);
  const nodes = waiting.map((r) => {
    const isBusy = busy.has(r.event_id);
    const card = cards.get(r.event_id);
    if (card && card.row === r && card.busy === isBusy && card.canAct === canAct) return card.node;
    const actions = canAct
      ? [
          el("button", { disabled: isBusy, onclick: () => override(r, "approve") }, "Approve"),
          el("button", { disabled: isBusy, onclick: () => override(r, "deny") }, "Deny"),
        ]
      : [el("p", { className: "read-only" }, READ_ONLY)];
    const node = el("div", { className: "card" },
      el("p", { className: "what" }, what(r)),
      el("p", {}, `${why(r)}. Asked by ${who(r)}.`),
      ...actions,
    );
    cards.set(r.event_id, { row: r, busy: isBusy, canAct, node });
    return node;
  });
  const box = document.getElementById("needs-ok");
  const want = nodes.length ? nodes : [nothingWaiting];
  if (want.length !== box.children.length || want.some((node, i) => box.children[i] !== node)) {
    box.replaceChildren(...want);
  }
}

function renderMeters(allowed) {
  const byCategory = new Map();
  for (const r of allowed) {
    const category = text(r.category, "other");
    byCategory.set(category, (byCategory.get(category) || 0) + cents(r));
  }
  const giftCards = byCategory.get("gift_card") || 0;
  const others = [...byCategory].filter(([category]) => category !== "gift_card");
  document.getElementById("meters").replaceChildren(
    el("p", {},
      `Gift cards: ${money(giftCards)} of ${money(LIMITS.gift_card_day)} `,
      el("meter", { min: 0, max: LIMITS.gift_card_day, value: giftCards }),
    ),
    ...others.map(([category, sum]) =>
      el("p", {}, `${lookup(CATEGORIES, category) || category.replaceAll("_", " ")}: ${money(sum)}`),
    ),
  );
}

function timelineItem(r) {
  return el("li", {},
    el("span", { className: "time" }, time(r)), " ",
    el("span", { className: `state ${state(r)}` }, stateLabel(r)), " ",
    what(r),
    r.status === "allowed" ? "" : el("div", { className: "why" }, `${why(r)}. Asked by ${who(r)}.`),
  );
}

draw();
loadLimits();
connect();
