"""The ledger's hash chain and verify(): the "edit one row by hand and the
check names the row" proof, plus the ways around it a judge will try next.

The append-only triggers are dropped first in every tampering test: that's
the step anyone with the file can take, and the chain is what's left.
"""

import hashlib
import json

import pytest

from guard import authorize, ledger


@pytest.fixture
def conn():
    c = ledger.connect(":memory:")
    for i, amount in enumerate([1_000, 2_000, 3_000, 4_000, 5_000], start=1):
        ledger.insert_event(c, ledger.utc_timestamp(), f"sess-{i}", "pay",
                            "grocer.example", amount, "ALLOW", scope_id="mom/bills-agent")
    c.commit()
    return c


def tamper(conn, sql, *params):
    conn.execute("DROP TRIGGER IF EXISTS prevent_event_updates")
    conn.execute("DROP TRIGGER IF EXISTS prevent_event_deletes")
    conn.execute("DROP TRIGGER IF EXISTS prevent_override_updates")
    conn.execute(sql, params)
    conn.commit()


def rehash_everything(conn):
    """What someone with the file and this source code does after an edit:
    recompute every hash so the chain is consistent again."""
    prev = ledger.GENESIS_HASH
    columns = ", ".join(ledger._EVENT_HASHED)
    for row_id, *values in conn.execute(
        f"SELECT id, {columns} FROM events ORDER BY id"
    ).fetchall():
        prev = ledger._chain_hash(prev, {"id": row_id, **dict(zip(ledger._EVENT_HASHED, values))})
        conn.execute("UPDATE events SET row_hash = ? WHERE id = ?", (prev, row_id))
    conn.commit()


def test_each_row_hashes_the_one_before_it(conn):
    """row_hash = sha256(previous row_hash + canonical JSON of the row), from
    a genesis of zeros - recomputed here by hand, not through ledger.py."""
    prev = "0" * 64
    columns = ("id",) + ledger._EVENT_HASHED
    for row in conn.execute(f"SELECT {', '.join(columns)}, row_hash FROM events ORDER BY id"):
        fields, stored = dict(zip(columns, row[:-1])), row[-1]
        payload = prev + json.dumps(fields, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False)
        assert stored == hashlib.sha256(payload.encode()).hexdigest()
        prev = stored
    assert ledger.verify(conn) == {"ok": True, "first_bad_event_id": None,
                                   "first_bad_override_id": None,
                                   "head": {"event_id": 5, "row_hash": prev}}


@pytest.mark.cedar
def test_a_real_day_verifies():
    """Every kind of row the guard writes - transfers, family payments,
    holds, the family's answers, breaker overrides - chains cleanly, and the
    dashboard's rows carry the same hashes."""
    conn = ledger.connect(":memory:")
    authorize.authorize_transfer(conn, "s1", "acct-1234", 999_900, scope_id="agent-a")
    authorize.authorize_transfer(conn, "s1", "acct-1234", 999_900, scope_id="agent-a")
    held = authorize.authorize_payment(
        conn, person="mom", chain=["mom", "bills-agent"], tool="buy_gift_card",
        amount_cents=5_000, payee="giftcards.example", category="gift_card",
        session_id="s2", tainted=True,
    )
    authorize.resolve(conn, held["event_id"], "approve", "daughter")
    ledger.insert_override(conn, ledger.utc_timestamp(), "agent-a", "daughter", "reset")
    conn.commit()

    result = ledger.verify(conn)
    assert result["ok"], result
    rows = ledger.contract_rows(conn)
    assert rows[-1]["row_hash"] == result["head"]["row_hash"]
    assert len({r["row_hash"] for r in rows}) == len(rows)


def test_editing_a_row_by_hand_names_that_row(conn):
    """The proof-panel demo: knock $40 off row 3 and the check names row 3."""
    tamper(conn, "UPDATE events SET amount_cents = 0 WHERE id = 3")
    result = ledger.verify(conn)
    assert result["ok"] is False and result["first_bad_event_id"] == 3


def test_deleting_a_row_names_the_one_after_it(conn):
    tamper(conn, "DELETE FROM events WHERE id = 3")
    assert ledger.verify(conn)["first_bad_event_id"] == 4


def test_slipping_a_row_in_is_caught(conn):
    tamper(conn, "UPDATE events SET id = 7 WHERE id = 5")
    ledger.insert_event(conn, ledger.utc_timestamp(), "sess-x", "pay", "x", 1, "ALLOW")
    conn.commit()
    assert ledger.verify(conn)["ok"] is False


def test_deleting_the_last_row_is_caught_by_an_anchor(conn):
    """The chain can't see a row cut off the end - nothing comes after it to
    disagree. A head() kept off the box (on the dashboard, in a phone
    alert) can."""
    anchor = ledger.head(conn)
    tamper(conn, "DELETE FROM events WHERE id = 5")
    assert ledger.verify(conn)["ok"] is True
    assert ledger.verify(conn, anchor=anchor)["first_bad_event_id"] == 5


def test_rewriting_and_rehashing_is_caught_by_an_anchor(conn):
    """The judge's follow-up: edit a row, then recompute every hash after it.
    The chain is consistent again, but it no longer ends where the anchor
    says it did."""
    anchor = ledger.head(conn)
    tamper(conn, "UPDATE events SET amount_cents = 0 WHERE id = 2")
    rehash_everything(conn)
    assert ledger.verify(conn)["ok"] is True
    result = ledger.verify(conn, anchor=anchor)
    assert result["ok"] is False and result["first_bad_event_id"] == 5


def test_with_a_key_rehashing_without_it_fails(monkeypatch):
    """With ACCRUE_LEDGER_KEY set, the hash is an HMAC under a key the
    guard process holds and the file doesn't. Someone who edits a row and
    rehashes with the code but not the key is caught at that row."""
    monkeypatch.setenv("ACCRUE_LEDGER_KEY", "held-by-the-guard-process")
    conn = ledger.connect(":memory:")
    for i in range(1, 4):
        ledger.insert_event(conn, ledger.utc_timestamp(), f"s{i}", "pay", "x", 100 * i, "ALLOW")
    conn.commit()
    assert ledger.verify(conn)["ok"] is True

    monkeypatch.delenv("ACCRUE_LEDGER_KEY")
    tamper(conn, "UPDATE events SET amount_cents = 0 WHERE id = 2")
    rehash_everything(conn)

    monkeypatch.setenv("ACCRUE_LEDGER_KEY", "held-by-the-guard-process")
    assert ledger.verify(conn)["first_bad_event_id"] == 1


def test_editing_an_override_is_caught(conn):
    """Overrides decide when the breaker lets go, so they're chained too:
    moving one's cut-off to cover later denials is caught."""
    ledger.insert_override(conn, ledger.utc_timestamp(), "mom", "daughter", "checked")
    ledger.insert_override(conn, ledger.utc_timestamp(), "mom", "daughter", "again")
    conn.commit()
    assert ledger.verify(conn)["ok"] is True

    tamper(conn, "UPDATE overrides SET after_event_id = 999 WHERE id = 1")
    result = ledger.verify(conn)
    assert result["ok"] is False
    assert result["first_bad_override_id"] == 1 and result["first_bad_event_id"] is None
