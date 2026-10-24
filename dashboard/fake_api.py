"""A stand-in for the guard's API, so the dashboard can be built before
guard/api.py exists. It speaks the contract in CLAUDE.md:

    GET  /events?since=<id>   rows with event_id > id, oldest first
    GET  /stream              the same rows as server-sent events, live
    POST /override            {event_id, action: approve|deny}

and plays a scripted day for Mom: two normal payments, then a gift-card
scam that switches to Zelle and a sub-agent until payments pause, then a
plumber's bill caught in the pause. It also serves the dashboard, so one
command runs both:

    python3 dashboard/fake_api.py              # prints the dashboard link
    python3 dashboard/fake_api.py --step 1     # a new payment every second
    python3 dashboard/fake_api.py --host 0.0.0.0   # reachable from a phone

Approving needs the dashboard's token, the same rule the real guard
follows: POST /override must send `Authorization: Bearer <token>`. The token
comes from ACCRUE_DASHBOARD_TOKEN, or is made up at startup, and the printed
link carries it as #token=... for the dashboard to pick up. The agent never
gets it. Reading /events and /stream needs no token.

Nothing here is real: no Cedar, no money, and the hashes chain only
within this process.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).parent
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
MAX_BODY = 10_000  # bytes; an /override body is about 40
MAX_STREAMS = 50  # live /stream connections at once
TIMEOUT = 30  # seconds before a stalled connection is dropped

BILLS = ["mom", "bills-agent"]
SUBAGENT = ["mom", "bills-agent", "giftcard-subagent"]
PAUSED = "Payments are paused after 3 blocked attempts in 10 minutes."

# Mom's day: tool, amount_cents, payee, category, chain, decision, rule,
# explanation. The decisions follow the normal column of CLAUDE.md's
# spending rules ($500 a day, $100 of gift cards, $200 to a new payee,
# 3 denials in 10 minutes and everything holds).
SCRIPT = [
    ("pay_bill", 12000, "ohio-power.example", "utility", BILLS, "allow", None,
     "Power bill, in line with last month's."),
    ("buy_gift_card", 5000, "giftcards.example", "gift_card", BILLS, "allow", None,
     "Birthday gift card, under today's $100 gift card limit."),
    ("buy_gift_card", 45000, "giftcards.example", "gift_card", BILLS, "deny",
     "gift_card_daily_cap", "That would make $500 in gift cards today. The limit is $100."),
    ("buy_gift_card", 45000, "giftcards.example", "gift_card", BILLS, "deny",
     "gift_card_daily_cap", "That would make $500 in gift cards today. The limit is $100."),
    ("send_zelle", 45000, "zelle:new-contact", "transfer", BILLS, "deny",
     "new_payee_cap", "A first payment to someone new is limited to $200."),
    ("buy_gift_card", 30000, "giftcards.example", "gift_card", SUBAGENT, "hold",
     "breaker", PAUSED),
    ("pay_bill", 18000, "plumber.example", "home_repair", BILLS, "hold",
     "breaker", PAUSED),
]
STATUS = {"allow": "allowed", "deny": "released", "hold": "held"}

DEMO_SCENARIOS = {
    "normal_day": SCRIPT[:2],
    "gift_card_scam": SCRIPT[2:4],
    "channel_switch": SCRIPT[4:6],
    "held_bill": SCRIPT[6:7],
}

DEMO_ORDER = [
    "normal_day",
    "gift_card_scam",
    "channel_switch",
    "held_bill",
]

class FakeGuard:
    """Event rows in memory, plus a feed of every row as it was added or
    changed, which /stream clients follow."""

    def __init__(self, first_id=1):
        self.rows = {}
        self.feed = []
        self.cond = threading.Condition()
        self._first_id = first_id
        self._prev_hash = "0" * 64
        self.demo_running = False
        self.demo_enabled = False
        self.demo_next_index = 0

    def add(self, tool, amount_cents, payee, category, chain, decision, rule, explanation):
        with self.cond:
            row = {
                "event_id": self._first_id + len(self.rows),
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": STATUS[decision], "person": chain[0], "chain": list(chain),
                "tool": tool, "amount_cents": amount_cents, "payee": payee,
                "category": category, "decision": decision, "rule": rule,
                "explanation": explanation, "flagged": decision != "allow",
            }
            body = json.dumps(row, sort_keys=True, separators=(",", ":"))
            self._prev_hash = hashlib.sha256((self._prev_hash + body).encode()).hexdigest()
            row["row_hash"] = self._prev_hash
            self._publish(row)
            return row

    def override(self, event_id, action):
        """Approve or deny a held row and return it. Raises KeyError for an
        unknown row and ValueError for one that isn't waiting."""
        with self.cond:
            row = self.rows[event_id]
            if row["status"] != "held":
                raise ValueError(f"event {event_id} is {row['status']}, not held")
            decision = "allow" if action == "approve" else "deny"
            row = {**row, "decision": decision, "status": STATUS[decision]}
            self._publish(row)
            return row

    def since(self, event_id):
        with self.cond:
            return [row for i, row in sorted(self.rows.items()) if i > event_id]

    def _publish(self, row):
        self.rows[row["event_id"]] = row
        self.feed.append(row)
        self.cond.notify_all()


class Handler(BaseHTTPRequestHandler):
    guard = None  # a FakeGuard, set by make_server
    streams = None  # a semaphore capping live /stream connections, set by make_server
    token = None  # the dashboard's secret for /override, set by make_server
    timeout = TIMEOUT

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/demo/status":
            with self.guard.cond:
                return self._json(200, {
                    "running": self.guard.demo_running,
                    "enabled": self.guard.demo_enabled,
                })
        if url.path in STATIC:
            name, content_type = STATIC[url.path]
            return self._send(200, (HERE / name).read_bytes(), content_type)
        if url.path == "/events":
            try:
                since = int(parse_qs(url.query).get("since", ["0"])[0])
            except ValueError:
                return self._json(400, {"error": "since must be an integer"})
            return self._json(200, self.guard.since(since))
        if url.path == "/stream":
            return self._stream()
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path == "/demo/run":
            return self._run_demo()
        if urlparse(self.path).path != "/override":
            return self._json(404, {"error": "not found"})
        # JSON only: a web page can send a text/plain POST to any address
        # without asking first, and the old handler parsed it anyway. A
        # JSON body with a token header makes the browser ask (CORS) first.
        if self.headers.get_content_type() != "application/json":
            return self._json(415, {"error": "the body must be JSON"})
        if not self._from_dashboard():
            return self._json(401, {"error": "approving needs the dashboard's token"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json(400, {"error": "bad Content-Length"})
        if not 0 <= length <= MAX_BODY:
            return self._json(413, {"error": f"the body must be at most {MAX_BODY} bytes"})
        try:
            body = json.loads(self.rfile.read(length))
            event_id, action = body["event_id"], body["action"]
            if type(event_id) is not int or action not in ("approve", "deny"):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self._json(400, {"error": "expected {event_id: int, action: approve|deny}"})
        try:
            self._json(200, self.guard.override(event_id, action))
        except KeyError:
            self._json(404, {"error": f"no event {event_id}"})
        except ValueError as err:
            self._json(409, {"error": str(err)})

    
    def _run_demo(self):
        # Simulator is available only in manual mode.
        if not self.guard.demo_enabled:
            return self._json(
                409, {"error": "Start the server with --manual"}
            )

        # Same token protection as /override.
        if self.headers.get_content_type() != "application/json":
            return self._json(415, {"error": "JSON required"})

        if not self._from_dashboard():
            return self._json(401, {"error": "Dashboard token required"})

        try:
            length = int(self.headers.get("Content-Length") or 0)

            if not 0 < length <= MAX_BODY:
                return self._json(413, {"error": "Invalid body size"})

            body = json.loads(self.rfile.read(length))
            scenario = body.get("scenario") if isinstance(body, dict) else None

        except (ValueError, TypeError):
            return self._json(400, {"error": "Invalid request"})

        if not isinstance(scenario, str) or scenario not in DEMO_SCENARIOS:
            return self._json(400, {"error": "Unknown scenario"})

        with self.guard.cond:
            if self.guard.demo_running:
                return self._json(409, {
                    "error": "Demo already running"
                })

            if self.guard.demo_next_index >= len(DEMO_ORDER):
                return self._json(409, {
                    "error": "Demo complete. Reset to run again."
                })

            expected = DEMO_ORDER[self.guard.demo_next_index]

            if scenario != expected:
                return self._json(409, {
                    "error": f"Run {expected} next"
                })

            self.guard.demo_running = True

        def run_scenario():
            completed = False

            try:
                for row in DEMO_SCENARIOS[scenario]:
                    time.sleep(1.5)
                    self.guard.add(*row)

                completed = True

            finally:
                with self.guard.cond:
                    if completed:
                        self.guard.demo_next_index += 1

                    self.guard.demo_running = False


        threading.Thread(
            target=run_scenario,
            daemon=True
        ).start()

        return self._json(202, {"started": scenario})

    
    def _stream(self):
        # Parsed before any header goes out: "²" passes isdigit() but not int().
        try:
            last = int(self.headers.get("Last-Event-ID") or 0)
        except ValueError:
            last = 0
        if not self.streams.acquire(blocking=False):
            return self._json(503, {"error": "too many live connections"})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self._cors()
            self.end_headers()
            guard = self.guard
            with guard.cond:
                pending, seen = guard.since(last), len(guard.feed)
            while True:
                for row in pending:
                    # An id line only for new rows: a changed old row must
                    # not move the browser's Last-Event-ID backwards.
                    new = row["event_id"] > last
                    last = max(last, row["event_id"])
                    head = f"id: {row['event_id']}\n" if new else ""
                    self.wfile.write(f"{head}data: {json.dumps(row)}\n\n".encode())
                if not pending:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
                with guard.cond:
                    guard.cond.wait_for(lambda: len(guard.feed) > seen, timeout=15)
                    pending, seen = guard.feed[seen:], len(guard.feed)
        except OSError:
            pass  # the browser went away or stopped reading
        finally:
            self.streams.release()

    def _from_dashboard(self):
        scheme, _, sent = self.headers.get("Authorization", "").partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(sent.encode(), self.token.encode())

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _json(self, code, data):
        self._send(code, json.dumps(data).encode(), "application/json")

    def _send(self, code, body, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the terminal quiet


def make_server(guard, token, host="127.0.0.1", port=8001, max_streams=MAX_STREAMS):
    if not token:
        raise ValueError("the dashboard token can't be empty")
    handler = type("BoundHandler", (Handler,), {
        "guard": guard, "streams": threading.BoundedSemaphore(max_streams), "token": token,
    })
    return ThreadingHTTPServer((host, port), handler)


def play(guard, step):
    for row in SCRIPT:
        time.sleep(step)
        guard.add(*row)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Fake guard API that also serves the dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="0.0.0.0 to open it from a phone")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--step", type=float, default=3.0, help="seconds between scripted payments (default 3)")
    parser.add_argument("--manual", action="store_true", help="Wait for manually triggered demo scenarios")
    args = parser.parse_args(argv)

    # Ids start at the current time in milliseconds, so they keep rising
    # across restarts: a dashboard or alert watcher left running doesn't
    # sit waiting for ids it has already seen.
    guard = FakeGuard(first_id=int(time.time() * 1000))
    guard.demo_enabled = args.manual
    token = os.environ.get("ACCRUE_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)
    server = make_server(guard, token, args.host, args.port)
    if not args.manual:
        threading.Thread(
        target=play,
        args=(guard, args.step),
        daemon=True
    ).start()
    base = f"http://{args.host}:{args.port}/"
    print(f"dashboard, can approve:  {base}#token={token}")
    print(f"dashboard, read-only:    {base}")
    print("(open the first link once on each device that should approve; Ctrl-C to stop)",
          flush=True)  # show the links even when output goes to a file
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
