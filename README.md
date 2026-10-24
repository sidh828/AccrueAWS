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

# the family dashboard against a stand-in API (until guard/api.py exists):
# open http://127.0.0.1:8001/ and watch Mom's scripted day arrive
python3 dashboard/fake_api.py
python3 dashboard/alerts.py --dry-run   # phone alerts, printed instead of sent
```

## Layout

The interface contract, invariants, spending rules and who owns which folder
are in [CLAUDE.md](CLAUDE.md).
