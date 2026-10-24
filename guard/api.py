"""HTTP API for payment authorization and the inbound/outbound safety walls."""
from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from guard import authorize, ledger
from guard.tool_contract import category_matches_tool
from walls.inbound import InboundWall, SessionStore
from walls.outbound import OutboundWall
from walls.secrets import SecretStore
from walls.storage import WallStateStore

logger = logging.getLogger(__name__)

class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class AuthorizeRequest(StrictRequest):
    person: str = Field(min_length=1)
    chain: list[str] = Field(min_length=1)
    tool: str = Field(min_length=1)
    amount_cents: int = Field(gt=0)
    payee: str = Field(min_length=1)
    category: str = Field(min_length=1)
    reason: str = ""
    request_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)


class InboundRequest(StrictRequest):
    session_id: str = Field(min_length=1)
    source: str
    content: str


class OutboundRequest(StrictRequest):
    session_id: str = Field(min_length=1)
    recipient: str = Field(min_length=1)
    channel: str = Field(min_length=1)
    content: str


def _database_path(path: str | Path | None) -> str:
    return str(path or os.environ.get("ACCRUE_DB_PATH", "ledger.db"))


def _configured_contacts() -> set[str]:
    return {
        contact.strip()
        for contact in os.environ.get("ACCRUE_ALLOWED_CONTACTS", "").split(",")
        if contact.strip()
    }


def create_app(
    db_path: str | Path | None = None,
    contacts: set[str] | None = None,
    wall_key: str | bytes | None = None,
) -> FastAPI:
    configured_key = wall_key if wall_key is not None else os.environ.get("ACCRUE_WALL_KEY")
    if configured_key is None:
        raise ValueError("ACCRUE_WALL_KEY must be set to persist verification-code digests")
    if not isinstance(configured_key, (str, bytes)):
        raise ValueError("ACCRUE_WALL_KEY must be text or bytes")
    code_key = configured_key.encode("utf-8") if isinstance(configured_key, str) else configured_key
    if len(code_key) < 32:
        raise ValueError("ACCRUE_WALL_KEY must contain at least 32 bytes")

    app = FastAPI(title="Accrue Guard")
    app.state.db_path = _database_path(db_path)
    wall_storage = WallStateStore(app.state.db_path, code_key)
    app.state.sessions = SessionStore(storage=wall_storage)
    app.state.secrets = SecretStore(storage=wall_storage)
    app.state.inbound_wall = InboundWall(app.state.sessions, app.state.secrets)
    app.state.outbound_wall = OutboundWall(
        app.state.secrets,
        app.state.sessions,
        contacts=_configured_contacts() if contacts is None else contacts,
    )

    @contextmanager
    def open_database() -> Iterator[sqlite3.Connection]:
        conn = ledger.connect(app.state.db_path)
        try:
            yield conn
        finally:
            conn.close()

    @app.post("/authorize")
    def authorize_request(body: AuthorizeRequest, request: Request):
        if not category_matches_tool(body.tool, body.category):
            raise HTTPException(status_code=422, detail="tool and category do not match")

        try:
            with open_database() as conn:
                return authorize.authorize_payment(
                    conn,
                    person=body.person,
                    chain=body.chain,
                    tool=body.tool,
                    amount_cents=body.amount_cents,
                    payee=body.payee,
                    category=body.category,
                    session_id=body.session_id,
                    request_id=body.request_id,
                    reason=body.reason,
                    tainted=request.app.state.sessions.is_tainted(body.session_id),
                )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except sqlite3.Error:
            logger.exception("Payment authorization failed because the ledger is unavailable")
            return {
                "decision": "hold",
                "rule": "database_unavailable",
                "totals": {},
                "limits": {},
                "needs_approval": True,
                "event_id": None,
            }

    @app.post("/inbound")
    def inbound(body: InboundRequest, request: Request):
        result = request.app.state.inbound_wall.ingest(
            body.session_id, body.source, body.content
        )
        return result.to_contract()

    @app.post("/outbound")
    def outbound(body: OutboundRequest, request: Request):
        return request.app.state.outbound_wall.check(
            body.session_id, body.recipient, body.channel, body.content
        )

    return app
