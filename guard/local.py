"""The guard in-process: the same answers as guard/api.py, with no server.

Benji's agent tools take any object with authorize(req), inbound(...) and
outbound(...) - agent.tools.HttpGuard talks to the running API, and this
calls the same code directly. It exists for the attack suite and other
scripted runs that move a fake clock: over HTTP the guard reads the real
time, so a "$49 every 20 minutes for a day" attack can't be replayed in a
second. Here the guard and the walls read `clock` instead.

    from guard.local import LocalGuard
    tools = ToolBox(LocalGuard(clock=fake_clock))

Two extras for the suite: `fault` - set it, and the rules engine is
unreachable for the next payments (they must hold), and verify(), the
ledger's hash-chain check (GET /verify).
"""

import contextlib
import tempfile
import time
from pathlib import Path
from datetime import datetime, timezone

from walls.inbound import InboundWall, SessionStore
from walls.outbound import OutboundWall
from walls.secrets import SecretStore

from . import api, authorize, ledger


class LocalGuard:
    def __init__(self, db_path=None, clock=time.time, contacts=None):
        self.clock = clock
        self.fault = None  # e.g. "cedar killed": Cedar can't be reached while it's set
        # A file, not ":memory:": the suite calls from many threads at once,
        # and each call gets its own connection, as in the server - so
        # parallel requests really do race for the ledger's write lock.
        if db_path is None:
            self._tmp = tempfile.TemporaryDirectory()
            db_path = str(Path(self._tmp.name) / "ledger.db")
        self._db_path = db_path
        ledger.connect(db_path).close()
        self.sessions = SessionStore(clock=clock)
        secrets = SecretStore(clock=clock)
        self._inbound = InboundWall(self.sessions, secrets)
        self._outbound = OutboundWall(secrets, self.sessions, contacts=contacts or set())

    @contextlib.contextmanager
    def _ledger(self):
        conn = ledger.connect(self._db_path)
        try:
            yield conn
        finally:
            conn.close()

    def authorize(self, req):
        now = datetime.fromtimestamp(self.clock(), tz=timezone.utc)
        with self._cedar():
            status, body = api.answer_authorize(self._ledger, req, self.sessions, now=now)
        return body if status in (200, 503) else {**api.UNAVAILABLE, "error": body["error"]}

    def inbound(self, session_id, source, content):
        return self._inbound.ingest(session_id, source, content).to_contract()

    def outbound(self, session_id, recipient, channel, content):
        return self._outbound.check(session_id, recipient, channel, content)

    def verify(self):
        with self._ledger() as conn:
            return ledger.verify(conn)

    @contextlib.contextmanager
    def _cedar(self):
        if not self.fault:
            yield
            return
        saved, authorize.CEDAR_BIN = authorize.CEDAR_BIN, "/nonexistent/cedar"
        try:
            yield
        finally:
            authorize.CEDAR_BIN = saved
