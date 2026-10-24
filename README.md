# Accrue

**History-aware spending limits for AI agents.**

Every guard on an AI agent today checks one request at a time. Scammers win
by spreading the damage out: over time, across payment methods, across
sub-agents, across parallel requests. Accrue checks the history, and proves
it holds.

> "No matter what anyone tells the agent, Mom can't lose more than $500 today."

The agent never touches the money. It can only *ask* the guard. The guard
reserves the amount, reads the running totals from a tamper-evident ledger,
asks [Cedar](https://www.cedarpolicy.com/) one question (given these totals,
is the next request over the limit?), and records the decision in the same
transaction. The family gets a live dashboard and a phone alert, and only
they can override.

## Built at HackOHI/O 2026

- **Before the event:** the accrue prototype, imported as-is in one commit
  tagged [`pre-event`](https://github.com/sidh828/AccrueAWS/tree/pre-event)
  from [dharvikgupta29/accrue](https://github.com/dharvikgupta29/accrue)
  at `14ac31c` (MIT).
- **Built this weekend:** everything after that tag. See
  [`pre-event...main`](https://github.com/sidh828/AccrueAWS/compare/pre-event...main).
- **How we used AI:** [AI_USAGE.md](AI_USAGE.md).

## Running it

```bash
# Cedar CLI: the guard shells out to it
cargo install cedar-policy-cli --version 4.12.0

python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest tests/ -q

# the original accrue demo: five $9,999 transfers against a $10,000
# budget. The first is allowed, the rest are denied.
.venv/bin/python -m guard.main

# the live guard API (agent tools call /authorize, /inbound and /outbound;
# the dashboard reads /events and /stream and approves through /override).
# It prints the dashboard links. Keys, generated once and kept stable and
# outside the database:
#   ACCRUE_WALL_KEY     keys the walls' stored code digests (32+ bytes); without
#                       it, taint and received codes are forgotten on restart
#   ACCRUE_LEDGER_KEY   keys the ledger's hash chain
#   ACCRUE_DASHBOARD_TOKEN  the dashboard's secret for approving (else made up)
#   ACCRUE_ALLOWED_CONTACTS comma-separated recipients /outbound always allows
#   ACCRUE_TOKEN_KEY    verifies agents' signed delegation tokens; with
#   ACCRUE_REQUIRE_TOKENS=1 a request without a valid token is refused.
#   Mint one for the agent:  ACCRUE_TOKEN_KEY=... python3 -m guard.tokens mint \
#                              --person mom --agent bills-agent --day 50000
#   A sub-agent narrows it (no key needed): python3 -m guard.tokens narrow TOKEN \
#                              --agent giftcard-subagent --day 10000 --tools buy_gift_card
# Generate a key with: python3 -c "import secrets; print(secrets.token_urlsafe(48))"
.venv/bin/python -m guard.api --db ledger.db
# Password-vault entries are still in memory and must be loaded at startup.

# the family dashboard against a stand-in API:
# It prints two links: the one ending in #token=... can approve payments
# (open it once on each device that should), the other is read-only.
python3 dashboard/fake_api.py
python3 dashboard/alerts.py --dry-run   # phone alerts, printed instead of sent
```

## Layout

The interface contract, invariants, spending rules and who owns which folder
are in [CLAUDE.md](CLAUDE.md).
