"""How long one decision takes, measured over HTTP against a real guard.

    python3 -m guard.bench --requests 1000

Starts a guard on a temporary ledger, sends /authorize requests one after
another (alternating with and without a signed delegation token), and
prints the p50, p95 and p99 round-trip times in milliseconds, with the
machine, Python and Cedar versions so the number means something later.
Each request is a 1-cent grocery payment, so all of them stay under every
limit and the timing is of the full allow path: lock, totals, Cedar,
record, commit.
"""

import argparse
import json
import platform
import secrets
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

from . import api, authorize, tokens


def percentile(sorted_ms, p):
    """The p-th percentile (nearest rank) of an already sorted list."""
    rank = max(1, -(-len(sorted_ms) * p // 100))  # ceil without floats in the rank
    return sorted_ms[rank - 1]


def cedar_version():
    try:
        out = subprocess.run([authorize.CEDAR_BIN, "--version"], capture_output=True,
                             text=True, timeout=5)
        return out.stdout.strip() or out.stderr.strip()
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def run(requests=1000):
    """Time `requests` decisions. Returns a dict of the results; times in ms."""
    token_key = secrets.token_bytes(32)
    agent_token = tokens.mint(token_key, "mom", agent="bills-agent", day_cents=50_000)
    role_tokens = {
        "agent": secrets.token_urlsafe(32),
        "viewer": secrets.token_urlsafe(32),
        "approver": secrets.token_urlsafe(32),
    }
    with tempfile.TemporaryDirectory() as tmp:
        server = api.make_server(str(Path(tmp) / "bench.db"), port=0,
                                 wall_key=secrets.token_bytes(32), token_key=token_key,
                                 role_tokens=role_tokens)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_address[1]}/authorize"
        timings = {"token": [], "no_token": []}
        decisions = {}
        try:
            for i in range(requests):
                body = {"person": "mom", "chain": ["mom", "bills-agent"], "tool": "pay_bill",
                        "amount_cents": 1, "payee": "kroger.example", "category": "groceries",
                        "session_id": "bench", "request_id": f"bench-{i}"}
                kind = "token" if i % 2 else "no_token"
                if kind == "token":
                    body["token"] = agent_token
                req = urllib.request.Request(url, json.dumps(body).encode(),
                                             {"Content-Type": "application/json",
                                              "Authorization": f"Bearer {role_tokens['agent']}"})
                start = time.perf_counter_ns()
                with urllib.request.urlopen(req) as resp:
                    decision = json.loads(resp.read())["decision"]
                timings[kind].append((time.perf_counter_ns() - start) / 1e6)
                decisions[decision] = decisions.get(decision, 0) + 1
        finally:
            server.shutdown()
            server.server_close()

    def summary(ms):
        ms = sorted(ms)
        return {"n": len(ms), "p50": percentile(ms, 50), "p95": percentile(ms, 95),
                "p99": percentile(ms, 99), "max": ms[-1]} if ms else {"n": 0}

    return {"all": summary(timings["token"] + timings["no_token"]),
            "token": summary(timings["token"]), "no_token": summary(timings["no_token"]),
            "decisions": decisions, "machine": f"{platform.machine()} {platform.system()} {platform.release()}",
            "python": platform.python_version(), "cedar": cedar_version()}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Time the guard's decisions over HTTP")
    parser.add_argument("--requests", type=int, default=1000)
    parser.add_argument("--json", action="store_true", help="print the raw results")
    args = parser.parse_args(argv)
    result = run(args.requests)
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"{args.requests} decisions over HTTP, one at a time ({result['decisions']})")
    print(f"machine: {result['machine']}, Python {result['python']}, {result['cedar']}")
    for kind, label in (("all", "all"), ("no_token", "without delegation"),
                        ("token", "with delegation")):
        s = result[kind]
        print(f"  {label:16} p50 {s['p50']:6.1f} ms   p95 {s['p95']:6.1f} ms   "
              f"p99 {s['p99']:6.1f} ms   max {s['max']:6.1f} ms   (n={s['n']})")


if __name__ == "__main__":
    main()
