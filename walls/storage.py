"""SQLite persistence for taint state and keyed verification-code digests."""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class WallStateStore:
    def __init__(self, db_path: str | Path, code_key: bytes):
        if len(code_key) < 32:
            raise ValueError("wall code key must contain at least 32 bytes")
        self._db_path = str(db_path)
        self._code_key = code_key
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS wall_sessions (
                    session_id TEXT PRIMARY KEY,
                    tainted INTEGER NOT NULL CHECK (tainted IN (0, 1)),
                    since REAL,
                    reasons TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS wall_received_codes (
                    code_digest TEXT PRIMARY KEY,
                    recorded_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_wall_received_codes_time
                    ON wall_received_codes (recorded_at);
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path, timeout=5)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def is_tainted(self, session_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tainted FROM wall_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        return bool(row and row[0])

    def taint(self, session_id: str, reason: str, now: float) -> None:
        self.taint_and_record_codes(session_id, reason, (), now)

    def taint_and_record_codes(
        self, session_id: str, reason: str, codes: tuple[str, ...], now: float
    ) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT since, reasons FROM wall_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            since = row[0] if row and row[0] is not None else now
            reasons = json.loads(row[1]) if row else []
            reasons.append(reason)
            conn.execute(
                """
                INSERT INTO wall_sessions (session_id, tainted, since, reasons)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    tainted = 1, since = excluded.since, reasons = excluded.reasons
                """,
                (session_id, since, json.dumps(reasons)),
            )
            conn.executemany(
                """
                INSERT INTO wall_received_codes (code_digest, recorded_at)
                VALUES (?, ?)
                ON CONFLICT(code_digest) DO UPDATE SET recorded_at = excluded.recorded_at
                """,
                ((self._digest(code), now) for code in codes),
            )

    def clear(self, session_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO wall_sessions (session_id, tainted, since, reasons)
                VALUES (?, 0, NULL, '[]')
                ON CONFLICT(session_id) DO UPDATE SET
                    tainted = 0, since = NULL, reasons = '[]'
                """,
                (session_id,),
            )

    def state(self, session_id: str) -> tuple[bool, float | None, list[str]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tainted, since, reasons FROM wall_sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
        if row is None:
            return False, None, []
        return bool(row[0]), row[1], json.loads(row[2])

    def record_code(self, code: str, now: float) -> None:
        self._validate_code(code)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO wall_received_codes (code_digest, recorded_at)
                VALUES (?, ?)
                ON CONFLICT(code_digest) DO UPDATE SET recorded_at = excluded.recorded_at
                """,
                (self._digest(code), now),
            )

    def matches_active_code(self, digit_stream: str, now: float, window: int) -> bool:
        candidates = {
            self._digest(digit_stream[start : start + length])
            for length in range(4, 9)
            for start in range(max(0, len(digit_stream) - length + 1))
        }
        if not candidates:
            return False
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM wall_received_codes WHERE recorded_at <= ?",
                (now - window,),
            )
            rows = conn.execute(
                "SELECT code_digest FROM wall_received_codes WHERE recorded_at > ?",
                (now - window,),
            ).fetchall()
        active = {row[0] for row in rows}
        return not candidates.isdisjoint(active)

    def _digest(self, code: str) -> str:
        self._validate_code(code)
        return hmac.new(self._code_key, code.encode("ascii"), hashlib.sha256).hexdigest()

    @staticmethod
    def _validate_code(code: str) -> None:
        if not code.isascii() or not code.isdigit() or not 4 <= len(code) <= 8:
            raise ValueError("verification codes must contain 4 to 8 ASCII digits")
