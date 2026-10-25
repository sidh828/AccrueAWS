# CLAUDE.md

Every Claude session on this repo reads this first. It holds the interface
contract and the invariants from the team plan. **The contract is frozen at
noon on Sat Oct 24.** Changing it after that needs everyone's agreement.

## What this is

Accrue is a guard between an AI agent and the money. The agent can only
*ask*. The guard reserves the amount, reads the running totals from a
tamper-evident ledger, asks Cedar one question (given these totals, is the
next request over the limit?), and records the decision in the same
transaction. The daughter gets a live dashboard and a phone alert, and only
she can override.

> "No matter what anyone tells the agent, Mom can't lose more than $500 today."

Everything at or before the `pre-event` tag is the accrue prototype, imported
as-is. Everything after it was built at HackOHI/O 2026.

## Rules for the weekend

- Contract frozen at noon. Changes after that need everyone's agreement.
- Push every hour. The commit graph is our evidence of what we built.
- Tier 1 works end to end before anyone touches Tier 2. The 6 PM gate is non-negotiable.
- Design freeze at 6 PM: polish after that, no new layouts.
- Stay in your own folder (see Layout). Ask before editing someone else's.
- Read every line Claude writes in your folder. Judges will ask about it on the live call.
- Log AI use in `AI_USAGE.md`: what we asked, what we rejected and why, how
  we checked it, which decisions a human made. Update at 2 PM, 6 PM and 11 PM.

## Invariants (we defend these on the live call)

- The agent holds no payment credentials and has no override tool.
- **Reserve before deciding.** Every request is recorded as pending inside a
  serialized transaction before Cedar is asked, so parallel requests can't
  both see the old total.
- **Fail closed.** If Cedar times out, crashes or the database errors, the
  answer is hold, never allow.
- **Tamper-evident.** Every ledger row carries a hash of the previous row.
  Editing history breaks the chain at that exact row.
- **Proven hierarchy.** Sub-agents carry signed tokens derived from their
  parent's; a child's budget can only be smaller.
- **Walls only tighten.** The inbound wall can only make rules stricter. The
  outbound wall blocks secrets deterministically; its AI labels never loosen
  anything.
- **No secret leaves.** The agent can never send out a verification code it
  received, a card or account number, or a password.
- The AI writes explanations only. Any number that doesn't match the ledger
  falls back to a fixed template.
- **Money is always integer cents. No floats anywhere.**

Deterministic checks do the blocking. AI only adds labels, and labels can
only tighten.

## Interface contract

**POST /authorize** (agent to guard)

```json
{"person": "mom", "token": "<signed delegation token>",
 "chain": ["mom", "bills-agent", "giftcard-subagent"],
 "tool": "buy_gift_card", "amount_cents": 45000,
 "payee": "giftcards.example", "category": "gift_card",
 "reason": "utility said power will be cut", "request_id": "uuid",
 "session_id": "conversation-1"}
```

Response (`totals` include this request; `limits` are the column that applied):

```json
{"decision": "deny", "rule": "gift_card_daily_cap",
 "totals": {"day": 62000, "gift_card_day": 50000, "recent_payees": 0},
 "limits": {"day": 50000, "gift_card_day": 10000, "new_payee_first": 20000,
            "recent_payees": 50000},
 "needs_approval": false, "event_id": 42}
```

**Event row** (from /events and /stream):

```json
{"event_id": 42, "ts": "2026-10-24T14:02:11.000000Z", "status": "released",
 "person": "mom", "chain": ["..."], "tool": "buy_gift_card",
 "amount_cents": 45000, "payee": "giftcards.example", "category": "gift_card",
 "decision": "deny", "rule": "gift_card_daily_cap", "explanation": "...",
 "flagged": true, "row_hash": "...", "notice": null, "known_bill": false,
 "resolved_by": null}
```

- `decision` is `allow`, `deny` or `hold`, and `needs_approval` is true exactly
  when it's `hold`. `status` is `allowed`, `released` or `held`. There's no
  `pending` row: the decision happens inside one locked transaction.
- **Approvals are new rows; nothing is ever edited.** On the wire, `/events`,
  `/stream` and `/override` send the held payment again under its own
  `event_id` with the family's decision, rule (`approved_by_family` /
  `denied_by_family`) and `resolved_by` (the resolving row's id).
- `notice`: `new_payee` / `recent_payee` on a payment that went through to
  someone new or first paid in the last 30 days - the FYI alert path.
  `known_bill`: the guard recognized a rent or utility bill; it's left out of
  the day's total. `explanation`: guard/explain.py, numbers checked.
- `token` (guard/tokens.py): a signed delegation. With one, the chain comes
  from the token and the request's is ignored; forged, altered or expired is
  a 401. `ACCRUE_REQUIRE_TOKENS=1` refuses requests without one.
- **HTTP role credentials are separate from delegation tokens.** The API
  requires distinct bearer credentials of at least 32 characters:
  `ACCRUE_AGENT_TOKEN`, `ACCRUE_VIEWER_TOKEN`, and
  `ACCRUE_APPROVER_TOKEN`. `ACCRUE_ADMIN_TOKEN` is optional and grants all
  authenticated API roles. `ACCRUE_DASHBOARD_TOKEN` is a temporary alias for
  the approver credential. Generate values with
  `python3 -c 'import secrets; print(secrets.token_urlsafe(24))'`.
- `POST /authorize`, `/inbound` and `/outbound`: agent or admin bearer
  credential. The agent bearer authenticates the client to the HTTP API; it
  does not replace the signed delegation `token` in `/authorize`.
- `GET /events?since=<id>` and `GET /stream` (server-sent events): payments
  ordered by `event_id`. Viewer, approver or admin bearer credential is
  required in the `Authorization` header. Do not put credentials in query
  strings; browser streams use `fetch` with an Authorization header.
- `GET /whoami`: any authenticated role. `GET /verify` and `GET /limits` stay
  open so the ledger fingerprint can be checked outside the dashboard.
- `POST /override {event_id, action: approve|deny}`: approver or admin
  credential and a JSON body, or it gets 401 or 415. The dashboard takes the
  approver credential from the `#token=` fragment; the agent never receives
  it, and phone alerts never carry it. An approval goes through even past a
  limit - the family is the override.
- `POST /replay {policy, since?}` (approver or admin): what a draft policy would
  have changed in real history. New rules can say `@outcome("hold")`.
- `POST /demo/run {scenario}`, `GET /demo/status` (guard started with
  `--demo`; approver or admin for run, viewer/approver/admin for status):
  the video's scenarios. Only the requests are scripted; the real guard
  decides.
- `POST /inbound {session_id, source, content}` -> `{trusted, tainted, labels}`.
  Untrusted text taints that session, and the whole household for 6 hours.
- `POST /outbound {session_id, recipient, channel, content}` ->
  `{decision: allow|redact|hold|block, findings}`. Every outbound send goes
  through this.
- The tool decides which categories it can pay (`authorize.TOOL_CATEGORIES`):
  `buy_gift_card` only `gift_card`, `send_zelle`/`send_wire` only `transfer`,
  `send_crypto` only `crypto`, `pay_bill` the household categories. Send
  `utility` or `rent` for bills; a plain `bill` is never a known bill.
- Money moves only through the payout outbox (`ledger.queued_payouts()`,
  `mark_sent()`): one payout per payment that went through. Never pay on an
  `/authorize` answer - a retried `request_id` returns the same one again.

## Spending rules

`guard/policies/family.cedar`. Each rule is one forbid with an `@id`;
`authorize.RULE_OUTCOMES` says whether it denies or holds. A deny beats a
hold; a rule the guard doesn't know denies.

| `rule` | Outcome | Normal | After a scam flag |
|---|---|---|---|
| `daily_cap` | deny | to someone new: over $500 in 24 h | over $100 |
| `daily_cap_needs_approval` | hold | to someone she's paid before: over $500 | over $100 |
| `gift_card_daily_cap` | deny | over $100 of gift cards in 24 h | - |
| `gift_card_needs_approval` | hold | - | any gift card |
| `new_payee_cap` | deny | first payment over $200 | - |
| `new_payee_month_cap` | hold | over $200 to a payee in its first 30 days | - |
| `new_payee_needs_approval` | hold | - | any first payment |
| `recent_payee_cap` | hold | over $500 in 30 days to payees first paid in them | any payment to them |
| `bill_increase` | hold | a known bill over last time + 20% | same |
| `breaker` | hold | 3 denials in 10 min | 1 denial |
| `delegation_tool`, `delegation_budget` | deny | a tool or branch budget the token doesn't grant | same |
| `guard_unavailable` | hold | the rules engine failed or timed out | same |

- "24 h" is rolling. The day's total leaves out known bills and payments the
  family approved.
- A known bill is a rent or utility payee last paid, as a bill, 20 to 45 days
  ago - once a cycle.
- The stricter column applies while the household is tainted (6 hours after
  untrusted text), when the session is, or when the request says so.
- Rules stay deterministic. The walls and the AI only decide which column
  applies, and only in the stricter direction.

## Implementation notes (guard)

- **Reservation:** `BEGIN IMMEDIATE` (SQLite serializes writers), read the
  totals, ask Cedar, record the decision and its payout, commit - one
  transaction. Tested with 50 at once landing exactly on the cap.
- **Fail closed:** Cedar has a 2 s timeout; any failure is a `hold`. A
  database failure is a 503 whose body is a hold.
- **Hash chain:** `row_hash = sha256(prev_hash + canonical_json(row))`, an HMAC
  with `ACCRUE_LEDGER_KEY`. `/verify` names the first bad row; an anchor
  catches a rewrite of everything after it.
- **Tokens:** macaroon-style chained HMAC (`ACCRUE_TOKEN_KEY`). The root is
  minted for Mom; each child adds a caveat (agent, smaller budget, fewer
  tools, expiry) and re-signs. The tightest caveat wins.
- **Latency, measured:** about 8 ms per decision over HTTP, 11 ms with a token.
- **Guarantees** are checked after the fact by `tests/guarantees.py`, which
  the property, concurrency and chaos tests all end with.

## Dashboard copy

Plain sentence-case English, readable on a projector ("Gift card blocked:
over today's limit"). Never "Cedar" or "ledger" on screen. Three states, used
everywhere the same way: allowed, waiting for you, stopped.

## Layout and owners

```
CLAUDE.md               contract + invariants; every Claude session reads this
guard/                  DHARVIK
  ledger.py             append-only SQLite log, hash-chained
  aggregates.py         totals: window, category, payee, across tools, incl. pending
  authorize.py          BEGIN IMMEDIATE -> reserve -> Cedar -> decide -> commit
  tokens.py             Tier 2: signed delegation tokens (chained HMAC)
  replay.py             Tier 2: run a draft policy against ledger history
  breaker.py            trips after N denials, ordered by row id
  explain.py            AI explanation + number checker + template fallback
  api.py                FastAPI: /authorize /override /events /stream /verify /replay /flag
  policies/family.cedar, family.cedarschema
agent/                  BENJI
  tools.py, agent.py    tools call the guard only; agent holds a token, no money
  scenarios/            normal day, gift cards, slow drip, Zelle, sub-agents
  attacks/              attack suite + scorer
  redteam.py            Tier 2: adaptive attacker agent + scoreboard
  mcp_proxy.py          Tier 2 (SIDDH): guard as an MCP server for Claude Desktop
walls/                  BENJI
  inbound.py            provenance + taint tracking; AI scam/injection labels
  outbound.py           secret detectors, recipient allowlist, redaction
  secrets.py            codes received, Luhn check, vault matches
dashboard/              SIDDH (styled from the designer's frames)
  index.html, app.js    dashboard, stream client, Approve/Deny
  rules.html            Tier 2: plain-English rule -> draft -> replay -> approve
  tree.js, proof.js     delegation tree; proof panel
  alerts.py             ntfy push
design/                 DESIGNER: Figma link, exported assets, thumbnail
tests/
  test_bugfixes.py, test_property.py, test_concurrency.py, test_chaos.py  (DHARVIK)
  test_walls.py         (BENJI) every attack in the attack suite as a test
README.md, AI_USAGE.md
```

## Running it

```bash
cargo install cedar-policy-cli --version 4.12.0   # the guard shells out to it
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest tests/ -q
```

Tests call the real `cedar` binary; they don't mock it.

The guard for the live demo (it serves the plain dashboard and prints its
links; the React app's dev proxy points at it):

```bash
ACCRUE_PEOPLE=mom ACCRUE_LEDGER_KEY=... ACCRUE_WALL_KEY=... \
ACCRUE_AGENT_TOKEN=... ACCRUE_VIEWER_TOKEN=... ACCRUE_APPROVER_TOKEN=... \
  .venv/bin/python -m guard.api --db ledger.db --demo
```

The three logins are required, unique and at least 32 characters each
(`python3 -c 'import secrets; print(secrets.token_urlsafe(24))'`). The agent's
process (and Claude Desktop's MCP config) gets only `ACCRUE_AGENT_TOKEN`.

Without `ACCRUE_PEOPLE` (or `ACCRUE_REQUIRE_TOKENS=1` with `ACCRUE_TOKEN_KEY`),
any "person" is accepted and each new one gets a fresh budget.

## Open questions

Settled ones are recorded on #1. Open items, with owners, are on #26.
