"""Isolated HTTP client for attack runs against the real Cedar-backed guard."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import urllib.request
from pathlib import Path

from guard import api, authorize
from agent.tools import HttpGuard


class LedgerGuard:
    """Run agent tools through HttpGuard against a fresh real API and ledger."""

    _cedar_lock = threading.RLock()

    def __init__(self, clock):
        cedar = os.environ.get("ACCRUE_CEDAR_BIN", authorize.CEDAR_BIN)
        cedar_path = shutil.which(cedar) or (cedar if Path(cedar).is_file() else None)
        if cedar_path is None:
            raise RuntimeError("real attack evidence requires the Cedar CLI")
        version = subprocess.run(
            [cedar_path, "--version"], capture_output=True, text=True, timeout=5, check=False
        )
        if version.returncode:
            raise RuntimeError(f"could not read Cedar version: {version.stderr.strip()}")

        self.cedar_path = str(Path(cedar_path).resolve())
        self.cedar_version = version.stdout.strip()
        self._previous_cedar_bin = authorize.CEDAR_BIN
        self._fault: str | None = None
        self._directory = tempfile.TemporaryDirectory(prefix="accrue-attack-")
        self.database_path = str(Path(self._directory.name) / "ledger.db")
        self.server = api.make_server(
            self.database_path,
            "attack-suite-dashboard-token",
            port=0,
            wall_key=secrets.token_bytes(32),
        )
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self._server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._server_thread.start()
        self.client = HttpGuard(self.base_url, timeout=30)
        with self._cedar_lock:
            authorize.CEDAR_BIN = self.cedar_path

    @property
    def fault(self) -> str | None:
        return self._fault

    @fault.setter
    def fault(self, value: str | None) -> None:
        self._fault = value
        with self._cedar_lock:
            authorize.CEDAR_BIN = (
                str(Path(self._directory.name) / "cedar-unavailable")
                if value else self.cedar_path
            )

    def authorize(self, req: dict) -> dict:
        return self.client.authorize(req)

    def inbound(self, session_id, source, content):
        return self.client.inbound(session_id, source, content)

    def outbound(self, session_id, recipient, channel, content):
        return self.client.outbound(session_id, recipient, channel, content)

    def evidence(self) -> dict:
        request = urllib.request.Request(self.base_url + "/verify")
        with urllib.request.urlopen(request, timeout=5) as response:
            verification = json.loads(response.read())
        head = verification["head"]
        return {
            "backend": "real_http_cedar_ledger",
            "cedar_version": self.cedar_version,
            "event_count": head["event_id"] if head else 0,
            "ledger_verification": verification,
        }

    def tamper_event(self, event_id: int = 1) -> None:
        conn = sqlite3.connect(self.database_path)
        try:
            conn.execute("DROP TRIGGER prevent_event_updates")
            conn.execute("UPDATE events SET reason = 'tampered' WHERE id = ?", (event_id,))
            conn.commit()
        finally:
            conn.close()

    def close(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
            self._server_thread.join(timeout=5)
            if self._server_thread.is_alive():
                raise RuntimeError("attack-suite guard server did not stop")
        finally:
            with self._cedar_lock:
                authorize.CEDAR_BIN = self._previous_cedar_bin
            self._directory.cleanup()
