"""Chaos: the rules engine and the database failing in every way we could
think of, including mid-run. The answer is always hold, never allow
(CLAUDE.md, "Fail closed"), and the guarantees still hold afterwards."""

import sqlite3
import threading

import pytest

from guard import api, authorize, ledger
from tests.guarantees import broken

pytestmark = pytest.mark.cedar

# Fake "cedar" binaries, each broken a different way. `exec` so a timeout's
# kill reaches the sleeping process.
BROKEN_CEDARS = {
    "crashes": "#!/bin/sh\nexit 1\n",
    "segfaults": "#!/bin/sh\nkill -SEGV $$\n",
    "hangs": "#!/bin/sh\nexec sleep 30\n",
    "says nothing": "#!/bin/sh\nexit 0\n",
    "says something else": "#!/bin/sh\necho MAYBE\nexit 0\n",
    "allows but a rule errored": (
        "#!/bin/sh\necho ALLOW\necho\necho \"error while evaluating policy \\`daily_cap\\`\"\nexit 0\n"),
    "allows with an odd exit code": "#!/bin/sh\necho ALLOW\nexit 7\n",
    "names a policy with junk": (
        "#!/bin/sh\necho DENY\necho\n"
        "echo 'note: this decision was due to the following policies:'\n"
        "echo '  daily_cap; rm -rf /'\nexit 2\n"),
}


def pay(conn, amount=1_000, payee="kroger.example", category="groceries"):
    return authorize.authorize_payment(
        conn, person="mom", chain=["mom", "bills-agent"], tool="pay_bill",
        amount_cents=amount, payee=payee, category=category, session_id="s")


@pytest.fixture
def known_grocer():
    conn = ledger.connect(":memory:")
    ledger.insert_event(conn, "2026-01-01T00:00:00.000000Z", "history", "pay", "kroger.example",
                        100, "ALLOW", scope_id="mom/bills-agent", payee="kroger.example",
                        category="groceries")
    conn.commit()
    return conn


@pytest.mark.parametrize("how", sorted(BROKEN_CEDARS))
def test_a_broken_rules_engine_always_holds(how, known_grocer, tmp_path, monkeypatch):
    fake = tmp_path / "cedar"
    fake.write_text(BROKEN_CEDARS[how])
    fake.chmod(0o755)
    monkeypatch.setattr(authorize, "CEDAR_BIN", str(fake))
    monkeypatch.setattr(authorize, "CEDAR_TIMEOUT_SECONDS", 0.5)

    response = pay(known_grocer)
    assert (response["decision"], response["rule"]) == ("hold", "guard_unavailable"), how
    assert broken(known_grocer) == []


def test_killing_the_rules_engine_mid_run(known_grocer, tmp_path, monkeypatch):
    """The proof panel's 'kill Cedar mid-demo': payments flow, the engine
    disappears halfway, payments keep coming. Everything before goes
    through as normal; everything after waits; nothing slips through."""
    decisions = [pay(known_grocer)["decision"] for _ in range(3)]
    monkeypatch.setattr(authorize, "CEDAR_BIN", str(tmp_path / "gone"))
    decisions += [pay(known_grocer)["decision"] for _ in range(3)]
    assert decisions == ["allow"] * 3 + ["hold"] * 3
    assert broken(known_grocer) == []


def test_a_read_only_ledger_answers_hold(tmp_path, monkeypatch):
    """The database refusing writes: /authorize answers a hold (with a
    503), never an allow, and the agent's tools treat it as not paid."""
    path = tmp_path / "ledger.db"
    ledger.connect(str(path)).close()
    path.chmod(0o444)

    def open_ledger():
        class Ctx:
            def __enter__(self):
                self.conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                return self.conn

            def __exit__(self, *exc):
                self.conn.close()
        return Ctx()

    body = {"person": "mom", "chain": ["mom", "bills-agent"], "tool": "pay_bill",
            "amount_cents": 1_000, "payee": "kroger.example", "category": "groceries",
            "session_id": "s"}

    class NoTaint:
        def is_tainted(self, session_id):
            return False

    status, answer = api.answer_authorize(open_ledger, body, NoTaint())
    assert status == 503
    assert (answer["decision"], answer["needs_approval"]) == ("hold", True)


def test_a_ledger_locked_by_someone_else_answers_hold(tmp_path, monkeypatch):
    """Another process holding the write lock longer than the busy timeout:
    the payment can't be recorded, so it isn't allowed."""
    path = str(tmp_path / "ledger.db")
    ledger.connect(path).close()
    blocker = sqlite3.connect(path)
    blocker.execute("BEGIN IMMEDIATE")

    def open_ledger():
        class Ctx:
            def __enter__(self):
                self.conn = ledger.connect(path)
                self.conn.execute("PRAGMA busy_timeout = 200")
                return self.conn

            def __exit__(self, *exc):
                self.conn.close()
        return Ctx()

    class NoTaint:
        def is_tainted(self, session_id):
            return False

    body = {"person": "mom", "chain": ["mom"], "tool": "pay_bill", "amount_cents": 1_000,
            "payee": "kroger.example", "category": "groceries", "session_id": "s"}
    try:
        status, answer = api.answer_authorize(open_ledger, body, NoTaint())
    finally:
        blocker.rollback()
        blocker.close()
    assert (status, answer["decision"]) == (503, "hold")


def test_engine_flapping_under_load_never_lets_anything_slip(tmp_path, monkeypatch):
    """Thirty payments from many threads while the engine flips between
    working and gone. Whatever each payment saw, the ledger afterwards
    breaks no guarantee and nothing allowed lacks a clean answer."""
    path = str(tmp_path / "ledger.db")
    conn = ledger.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    real = authorize.CEDAR_BIN
    stop = threading.Event()

    def flap():
        while not stop.is_set():
            authorize.CEDAR_BIN = str(tmp_path / "gone")
            stop.wait(0.01)
            authorize.CEDAR_BIN = real
            stop.wait(0.01)

    def worker(i):
        c = ledger.connect(path)
        try:
            authorize.authorize_payment(
                c, person="mom", chain=["mom", "bills-agent"], tool="send_zelle",
                amount_cents=4_000, payee=f"payee-{i % 7}.example", category="transfer",
                session_id="s")
        finally:
            c.close()

    flapper = threading.Thread(target=flap)
    flapper.start()
    try:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(30)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        stop.set()
        flapper.join()
        authorize.CEDAR_BIN = real

    conn = ledger.connect(path)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 30
    assert broken(conn) == []
