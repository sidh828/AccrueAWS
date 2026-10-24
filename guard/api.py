"""The guard's HTTP API: CLAUDE.md's interface contract over the real
ledger and Cedar.

    POST /authorize          agent -> guard: may this payment happen?
    POST /inbound            agent -> walls: {session_id, source, content}
    POST /outbound           agent -> walls: {session_id, recipient, channel, content}
    POST /override           dashboard only: {event_id, action: approve|deny}
    GET  /events?since=<id>  payments, oldest first
    GET  /stream             the same, live, as server-sent events
    GET  /verify             {ok, first_bad_event_id, first_bad_override_id, head}
                             (?anchor_id=&anchor_hash= checks a head kept elsewhere)
    GET  /limits             the spending limits, normal and after a scam flag
    GET  /, /app.js          the dashboard, served from dashboard/

    python3 -m guard.api                    # prints the dashboard links
    python3 -m guard.api --host 0.0.0.0     # reachable from a phone

It behaves like dashboard/fake_api.py on purpose, so the dashboard switches
from the stand-in to this without changes:

- /override needs `Authorization: Bearer <token>` and a JSON body, as in
  #9. The token is ACCRUE_DASHBOARD_TOKEN, or made up at startup and
  printed in the dashboard link. The agent never gets it.
- Rows are sent as payments, not ledger entries. The ledger never changes a
  row: approving a hold appends a row that resolves it. Sent as is, the
  dashboard would count an approved payment twice. So /events, /stream and
  /override send the held payment again under its own event_id, now with
  the decision and status the family gave it, a `resolved_by` (the
  resolving row's id) and the rule "approved_by_family" or
  "denied_by_family". /verify and the hash chain cover the ledger itself.

Fail closed: a request the guard can't answer because the database failed
gets a 503 whose body is a hold, never an allow. The agent's tools must
treat any error or timeout from here as "not paid" too.

Benji's walls (walls/) run inside the same server: /inbound tags where
text came from and taints the session for untrusted sources, /outbound
blocks codes Mom received and other secrets, and their state is kept in
the ledger's database (walls.storage) so it survives a restart. Taint can
only tighten: /authorize uses the stricter column whenever /inbound has
tainted the session, and a request's own "tainted": true is honored while
"false" is ignored.

Standard library only (http.server), like the stand-in.
"""

import argparse
import hmac
import json
import os
import secrets
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from walls.inbound import InboundWall, SessionStore
from walls.outbound import OutboundWall
from walls.secrets import SecretStore
from walls.storage import WallStateStore

from . import authorize, ledger

DASHBOARD = Path(__file__).parent.parent / "dashboard"
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
MAX_BODY = 10_000  # bytes; an /authorize body is a few hundred
MAX_STREAMS = 50  # live /stream connections at once
TIMEOUT = 30  # seconds before a stalled connection is dropped
STREAM_POLL = 1.0  # seconds between ledger checks when nothing woke a stream

# The /authorize fields passed through to authorize.authorize_payment.
REQUIRED = ("person", "chain", "tool", "amount_cents", "payee", "category", "session_id")
OPTIONAL = ("request_id", "reason")

# What the agent gets when the guard itself is down: a hold, never an allow.
UNAVAILABLE = {"decision": "hold", "rule": authorize.GUARD_UNAVAILABLE,
               "needs_approval": True, "event_id": None}


def answer_authorize(open_ledger, body, sessions, now=None):
    """POST /authorize's answer as (http_status, body), shared with
    guard.local.LocalGuard so the in-process guard behaves exactly like the
    server. `open_ledger()` returns a context manager yielding a
    connection; `sessions` has is_tainted(session_id)."""
    missing = [f for f in REQUIRED if f not in body]
    if missing:
        return 400, {"error": f"missing {', '.join(missing)}"}
    kwargs = {f: body[f] for f in REQUIRED + OPTIONAL if f in body}
    session_id = body["session_id"]
    kwargs["tainted"] = body.get("tainted") is True or (
        isinstance(session_id, str) and sessions.is_tainted(session_id)
    )
    try:
        with open_ledger() as conn:
            return 200, authorize.authorize_payment(conn, now=now, **kwargs)
    except ValueError as err:
        return 400, {"error": str(err)}
    except sqlite3.Error as err:
        return 503, {**UNAVAILABLE, "error": f"the ledger failed: {err}"}
    except Exception as err:  # anything else unexpected: still a hold
        return 503, {**UNAVAILABLE, "error": f"the guard failed: {err!r}"}


def payment_view(conn, event_id):
    """One payment as the dashboard sees it: the ledger row, or - if a later
    row approved or denied it - that row's decision, status and rule under
    the payment's own event_id, with `resolved_by` naming the later row."""
    view = ledger.contract_row(conn, event_id)
    if view is None:
        return None
    view.pop("resolves")
    view["resolved_by"] = None
    row = conn.execute("SELECT id FROM events WHERE resolves = ?", (event_id,)).fetchone()
    if row is not None:
        settled = ledger.contract_row(conn, row[0])
        view.update(decision=settled["decision"], status=settled["status"],
                    rule=settled["rule"], explanation=settled["explanation"],
                    resolved_by=settled["event_id"])
    return view


def payment_views(conn, since=0):
    """Every payment that gained a ledger row after `since` - new ones, and
    held ones that were just settled - as payment_view shows them, in
    event_id order. Also returns the last ledger id read, for the next
    call."""
    rows = ledger.contract_rows(conn, since)
    ids = sorted({row["resolves"] or row["event_id"] for row in rows})
    return [payment_view(conn, i) for i in ids], max((r["event_id"] for r in rows), default=since)


def limits():
    """The spending limits in cents, by column."""
    limit = authorize.FAMILY_LIMITS
    return {
        "normal": {"day": limit["day"], "gift_card_day": limit["gift_card_day"],
                   "new_payee_first": limit["new_payee_first"],
                   "recent_payees": limit["recent_payees"],
                   "breaker_denials": limit["breaker_denials"]},
        "flagged": {"day": limit["day_flagged"], "gift_card_day": 0, "new_payee_first": 0,
                    "recent_payees": limit["recent_payees_flagged"],
                    "breaker_denials": limit["breaker_denials_flagged"]},
    }


class Handler(BaseHTTPRequestHandler):
    # Set by make_server.
    db_path = None
    token = None
    sessions = None  # walls.inbound.SessionStore: taint, shared with /inbound
    inbound_wall = None
    outbound_wall = None
    streams = None  # a semaphore capping live /stream connections
    changed = None  # a Condition notified after every write, to wake streams
    timeout = TIMEOUT

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if url.path in STATIC:
            name, content_type = STATIC[url.path]
            path = DASHBOARD / name
            if not path.is_file():
                return self._json(404, {"error": "the dashboard isn't here"})
            return self._send(200, path.read_bytes(), content_type)
        if url.path == "/stream":
            return self._stream()
        if url.path == "/limits":
            return self._json(200, limits())
        if url.path == "/events":
            try:
                since = int(query.get("since", ["0"])[0])
            except ValueError:
                return self._json(400, {"error": "since must be an integer"})
            with self._ledger() as conn:
                return self._json(200, payment_views(conn, since)[0])
        if url.path == "/verify":
            anchor = None
            if "anchor_id" in query or "anchor_hash" in query:
                try:
                    anchor = {"event_id": int(query["anchor_id"][0]),
                              "row_hash": query["anchor_hash"][0]}
                except (KeyError, ValueError):
                    return self._json(400, {"error": "anchor needs anchor_id and anchor_hash"})
            with self._ledger() as conn:
                return self._json(200, ledger.verify(conn, anchor=anchor))
        self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/authorize", "/override", "/inbound", "/outbound"):
            return self._json(404, {"error": "not found"})
        # JSON only: a web page can send a text/plain POST anywhere without
        # asking first. A JSON body makes the browser ask (CORS) first.
        if self.headers.get_content_type() != "application/json":
            return self._json(415, {"error": "the body must be JSON"})
        if path == "/override" and not self._from_dashboard():
            return self._json(401, {"error": "approving needs the dashboard's token"})
        body = self._body()
        if body is None:
            return
        if path == "/authorize":
            return self._authorize(body)
        if path == "/inbound":
            return self._inbound(body)
        if path == "/outbound":
            return self._outbound(body)
        return self._override(body)

    def _authorize(self, body):
        status, response = answer_authorize(self._ledger, body, self.sessions)
        if status == 200:
            self._wake_streams()
        self._json(status, response)

    def _inbound(self, body):
        if not _strings(body, "session_id", "source", "content") or not body["session_id"]:
            return self._json(400, {"error": "expected {session_id, source, content} as strings"})
        result = self.inbound_wall.ingest(body["session_id"], body["source"], body["content"])
        self._json(200, result.to_contract())

    def _outbound(self, body):
        if (not _strings(body, "session_id", "recipient", "channel", "content")
                or not body["session_id"] or not body["recipient"]):
            return self._json(400, {"error": "expected {session_id, recipient, channel, "
                                             "content} as strings"})
        self._json(200, self.outbound_wall.check(body["session_id"], body["recipient"],
                                                 body["channel"], body["content"]))

    def _override(self, body):
        event_id, action = body.get("event_id"), body.get("action")
        if type(event_id) is not int or action not in ("approve", "deny"):
            return self._json(400, {"error": "expected {event_id: int, action: approve|deny}"})
        with self._ledger() as conn:
            if ledger.get_event(conn, event_id) is None:
                return self._json(404, {"error": f"no event {event_id}"})
            try:
                authorize.resolve(conn, event_id, action, "dashboard")
            except ValueError as err:
                return self._json(409, {"error": str(err)})
            view = payment_view(conn, event_id)
        self._wake_streams()
        self._json(200, view)

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
            cursor, quiet = last, 0.0
            with self._ledger() as conn:
                while True:
                    views, cursor = payment_views(conn, cursor)
                    for view in views:
                        # An id line only for new payments: a settled old one
                        # must not move the browser's Last-Event-ID backwards.
                        new = view["event_id"] > last
                        last = max(last, view["event_id"])
                        head = f"id: {view['event_id']}\n" if new else ""
                        self.wfile.write(f"{head}data: {json.dumps(view)}\n\n".encode())
                    quiet = 0.0 if views else quiet + STREAM_POLL
                    if quiet >= 15:
                        self.wfile.write(b": keepalive\n\n")
                        quiet = 0.0
                    self.wfile.flush()
                    # Woken at once by a write in this process; the timeout
                    # also picks up writes from anywhere else.
                    with self.changed:
                        self.changed.wait(timeout=STREAM_POLL)
        except OSError:
            pass  # the browser went away or stopped reading
        finally:
            self.streams.release()

    def _ledger(self):
        """A connection for this request (sqlite3 connections can't be
        shared across threads), closed when the block ends."""
        return _Connection(self.db_path)

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(400, {"error": "bad Content-Length"})
            return None
        if not 0 <= length <= MAX_BODY:
            self._json(413, {"error": f"the body must be at most {MAX_BODY} bytes"})
            return None
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            body = None
        if not isinstance(body, dict):
            self._json(400, {"error": "the body must be a JSON object"})
            return None
        return body

    def _wake_streams(self):
        with self.changed:
            self.changed.notify_all()

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


def _strings(body, *fields):
    return all(isinstance(body.get(f), str) for f in fields)


class _Connection:
    def __init__(self, db_path):
        self.db_path = db_path

    def __enter__(self):
        self.conn = ledger.connect(self.db_path)
        return self.conn

    def __exit__(self, *exc):
        self.conn.close()


def make_server(db_path, token, host="127.0.0.1", port=8000, wall_key=None,
                contacts=None, max_streams=MAX_STREAMS):
    """A server for the ledger at `db_path`. `token` is the dashboard's
    secret for /override. `wall_key` (32+ bytes) keys the walls' stored
    digests of received codes; with it, taint and received codes are kept
    in the database and survive a restart, without it they live in memory.
    `contacts` are the recipients /outbound always allows."""
    if not token:
        raise ValueError("the dashboard token can't be empty")
    storage = None
    if wall_key is not None:
        key = wall_key.encode() if isinstance(wall_key, str) else wall_key
        storage = WallStateStore(db_path, key)  # raises if the key is short
    sessions = SessionStore(storage=storage)
    secrets_store = SecretStore(storage=storage)
    conn = ledger.connect(db_path)
    if db_path != ":memory:":
        # Readers (the dashboard, /verify) don't wait for writers, or the
        # other way round.
        conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    handler = type("BoundHandler", (Handler,), {
        "db_path": db_path, "token": token, "sessions": sessions,
        "inbound_wall": InboundWall(sessions, secrets_store),
        "outbound_wall": OutboundWall(secrets_store, sessions, contacts=contacts or set()),
        "streams": threading.BoundedSemaphore(max_streams),
        "changed": threading.Condition(),
    })
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description="The guard's API; also serves the dashboard")
    parser.add_argument("--db", default="ledger.db", help="the ledger file (default ledger.db)")
    parser.add_argument("--host", default="127.0.0.1", help="0.0.0.0 to open it from a phone")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    token = os.environ.get("ACCRUE_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)
    wall_key = os.environ.get("ACCRUE_WALL_KEY")
    contacts = {c.strip() for c in os.environ.get("ACCRUE_ALLOWED_CONTACTS", "").split(",")
                if c.strip()}
    server = make_server(args.db, token, args.host, args.port, wall_key=wall_key,
                         contacts=contacts)
    base = f"http://{args.host}:{args.port}/"
    print(f"guard API on {base}  (ledger: {args.db})")
    print(f"dashboard, can approve:  {base}#token={token}")
    print(f"dashboard, read-only:    {base}")
    if not os.environ.get("ACCRUE_LEDGER_KEY"):
        print("note: ACCRUE_LEDGER_KEY isn't set, so the ledger is hashed without a key")
    if not wall_key:
        print("note: ACCRUE_WALL_KEY isn't set, so taint and received codes are kept in "
              "memory and forgotten on restart")
    print("(open the first link once on each device that should approve; Ctrl-C to stop)",
          flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
