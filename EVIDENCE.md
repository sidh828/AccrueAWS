# Evidence

Every number we say on the live call, the command that produced it, and
what it printed tonight. Run them yourself: they use the real `cedar`
binary (4.12.0), no mocks.

Measured Sat Oct 24, 8:00-9:00 PM, on an M-series MacBook (arm64, macOS
14.4, Python 3.15.0), at `main` `ca56b0e` plus this PR. The soak started just before the writer queue went
in. It makes one decision at a time, which the queue doesn't change; every
other row ran with it.

| Claim | Command | Tonight |
|---|---|---|
| **The cap holds under a storm.** 1,000 $1 payments released at the same instant land exactly on $500 | `ACCRUE_STORM=1000 .venv/bin/pytest tests/test_cap_storm.py -q -s` | 500 allowed ($500.00 exactly), 500 held, 0 lost, 0 timed out, in 12 s |
| **Concurrency keeps every guarantee.** Sub-agents, retries and a mixed crowd at once | `for i in $(seq 20); do .venv/bin/pytest tests/test_concurrency.py tests/test_chaos.py -q \|\| break; done` | 20 of 20 runs pass with the writer queue (the 7 concurrency tests plus the chaos tests each run) |
| **The rules hold on any history.** Random households, every limit, scam flags, approvals | `ACCRUE_PROPERTY_RUNS=10000 .venv/bin/pytest tests/test_property.py -q` | 10,000 households × 40 steps (about 400,000 decisions): 0 guarantees broken, in 38 min |
| **It fails closed.** Cedar killed, hanging, flapping; the ledger read-only or locked | `.venv/bin/pytest tests/test_chaos.py -q` | Every answer is a hold; nothing slips (with the chain, token and ledger tests: 45 pass) |
| **History is tamper-evident.** | Live, below | A plain edit is refused; with the lock removed, `/verify` names the row |
| **Every rule is tested by behavior.** Delete each rule and see whether a test fails | `.venv/bin/python tests/mutate_policy.py` | 12 of 12 rules caught |
| **The walls and caps hold against the attack suite** | `.venv/bin/python -m agent.attacks.attack_suite --real` | 18 attacks: 16 blocked, 2 capped (slow drip at $196, 50 at once at $200), nothing leaked |
| **It's fast.** One decision, over HTTP, end to end | `.venv/bin/python -m guard.bench --requests 1000` | p50 8.3 ms, p95 9.6 ms, p99 10.0 ms over 1,000 decisions. With a token: p50 8.4 ms, p99 10.2 ms |

## Tamper, step by step

```bash
sqlite3 demo.db "UPDATE events SET amount_cents = 100 WHERE id = 2;"
# Error: events are append-only

sqlite3 demo.db "DROP TRIGGER prevent_event_updates; UPDATE events SET amount_cents = 100 WHERE id = 2;"
curl -s http://127.0.0.1:8000/verify
# {"ok": false, "first_bad_event_id": 2, ...}
```

Before the edit, the same `/verify` said `{"ok": true, ...}`. Rewriting
every row after the edit is caught too, by passing an earlier `head` as
`?anchor_id=&anchor_hash=`.

## Found and fixed tonight

The storm test found that 500 or more requests at the same instant could
time out on the database lock. SQLite's wait sleeps in growing steps, so
most waiters slept through the lock being free. 600 at once: 308 timed out
(answered as holds, so safe, but real requests got held). `guard/authorize.py`
now queues writers in the process before SQLite's lock: 1,000 at once, 0
time out. Sequential decisions are unchanged.

## What we haven't measured

- **How often the model refuses on its own** (`agent/attacks/refusal_test.py`,
  the pitch's "X of 20") needs an API key. Benji runs it tonight; the number goes here with the model and date.
- The attack suite's model column is `NOT RUN` for the same reason.
- Latency is on one laptop, one request at a time, with the guard and
  client on the same machine.
