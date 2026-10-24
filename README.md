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
# Set a different random bearer credential for each role before starting.
# Credentials are kept outside the database:
#   ACCRUE_WALL_KEY     keys the walls' stored code digests (32+ bytes); without
#                       it, taint and received codes are forgotten on restart
#   ACCRUE_LEDGER_KEY   keys the ledger's hash chain
#   ACCRUE_AGENT_TOKEN  permits /authorize, /inbound and /outbound
#   ACCRUE_VIEWER_TOKEN permits dashboard and read-only API access
#   ACCRUE_APPROVER_TOKEN permits dashboard reads and /override
#   ACCRUE_ADMIN_TOKEN  optional; permits all API routes
# ACCRUE_DASHBOARD_TOKEN remains a temporary alias for ACCRUE_APPROVER_TOKEN.
# Each credential must be unique and at least 32 characters.
#   ACCRUE_ALLOWED_CONTACTS comma-separated recipients /outbound always allows
# Generate one credential at a time with:
#   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
.venv/bin/python -m guard.api --db ledger.db
# The startup output includes separate viewer and approver dashboard links.
# Use HTTPS or a trusted private network when binding beyond loopback.
# Password-vault entries are still in memory and must be loaded at startup.

# optional stand-in dashboard/API for a demo without the real guard:
# It prints two links: the one ending in #token=... can approve payments
# (open it once on each device that should), the other is read-only.
python3 dashboard/fake_api.py
python3 dashboard/alerts.py --dry-run   # phone alerts, printed instead of sent

# attack-suite comparison; --real sends agent requests through HttpGuard to a
# local real API backed by Cedar and an isolated ledger.
# The JSON report records the mode, Cedar version, source commit, ledger head,
# and verification result for each real-guard attack.
python3 -m agent.attacks.attack_suite --real --md attack-results.md --json attack-results.json
```

## Layout

The interface contract, invariants, spending rules and who owns which folder
are in [CLAUDE.md](CLAUDE.md).
