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
 "reason": "utility said power will be cut", "request_id": "uuid"}
```

Response:

```json
{"decision": "deny", "rule": "gift_card_daily_cap",
 "totals": {"day": 90000, "gift_card_day": 90000},
 "limits": {"day": 50000, "gift_card_day": 10000},
 "needs_approval": true, "event_id": 42}
```

**Event row** (from /events and /stream):

```json
{"event_id": 42, "ts": "2026-10-24T14:02:11Z", "status": "released",
 "person": "mom", "chain": ["..."], "tool": "buy_gift_card",
 "amount_cents": 45000, "payee": "giftcards.example", "category": "gift_card",
 "decision": "deny", "rule": "gift_card_daily_cap", "explanation": "...",
 "flagged": true, "row_hash": "..."}
```

- `decision` is `allow`, `deny` or `hold`. `status` is `pending`, `allowed`,
  `released` or `held`.
- `token` is optional until tokens land; the guard then requires it and
  ignores a bare chain.
- `GET /events?since=<id>` and `GET /stream` (server-sent events): rows
  ordered by `event_id`.
- `POST /override {event_id, action: approve|deny}`: dashboard only. The
  agent has no tool for it, and no credential: the request needs
  `Authorization: Bearer <dashboard token>` and a JSON body, or it gets 401
  or 415. The guard reads the token from `ACCRUE_DASHBOARD_TOKEN`, or makes
  one up and prints the dashboard link `…/#token=<token>`. The agent's
  process never has it, and phone alerts never carry it.
- `GET /verify`: `{ok, first_bad_event_id}`. `POST /replay {policy}`: what
  would have changed.
- `POST /inbound {session_id, source, content}` -> `{trusted, tainted, labels}`.
  Taint sticks to the session until the daughter clears it.
- `POST /outbound {session_id, recipient, channel, content}` ->
  `{decision: allow|redact|hold|block, findings}`. Every outbound send goes
  through this.
- Every request carries `session_id`; the guard reads the session's taint and
  uses the stricter column when tainted.

## Spending rules

| Rule | Normal limit | After a scam flag |
|---|---|---|
| Daily total | $500 | $100 |
| Gift cards per day | $100 | $0, needs approval |
| New payee, first payment | $200 | Needs approval |
| Known bills (utility, rent) | Up to last month + 20% | Unchanged |
| Breaker | 3 denials in 10 min: everything holds | 1 denial |

- The stricter column applies while the session is tainted, or after an AI
  scam label, for 6 hours.
- Rules stay deterministic. The walls and the AI only decide which column
  applies, and only in the stricter direction.

## Implementation notes (guard)

- **Reservation:** open with `BEGIN IMMEDIATE` (SQLite serializes writers),
  insert the request as `pending`, read totals including pending rows, ask
  Cedar, then mark `allowed` or `released`. Commit.
- **Hash chain:** `row_hash = sha256(prev_hash + canonical_json(row))`.
  `/verify` walks rows in id order and returns the first mismatch.
- **Tokens:** macaroon-style chained HMAC. The root token is minted for Mom
  with her limits; each child adds a caveat (smaller budget, narrower tools)
  and re-signs. The guard checks the whole chain and uses the tightest caveat.
- **Latency:** measure it, don't claim it. If shelling out to the Cedar CLI is
  slow, try the `cedarpy` bindings, but only if they install cleanly in 15
  minutes.
- **Known bugs in the imported code**, one commit each: breaker ordered by row
  id; lowercase scope names; indexed queries with a time window; timeout on
  the Cedar call.

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

## Open before the noon freeze

- The `/authorize` example has no `session_id`, but every request is
  supposed to carry one. Add it to the example?
- The response example is `"decision": "deny"` with `"needs_approval": true`.
  When does a request get `hold` instead, and what `status` does a request
  waiting for approval have (`held`)?
- `api.py` lists `/flag`, which the contract doesn't define. `/inbound` and
  `/outbound` are in the contract but not in `api.py`'s list. Which service
  serves the wall endpoints?
