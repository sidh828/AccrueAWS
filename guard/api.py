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
from walls.inbound import InboundWall, SessionStore
from walls.outbound import OutboundWall
from walls.secrets import SecretStore

logger = logging.getLogger(__name__)

TOOL_CATEGORIES = {
    "pay_bill": "bill",
    "buy_gift_card": "gift_card",
    "send_zelle": "transfer",
}


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
) -> FastAPI:
    app = FastAPI(title="Accrue Guard")
    app.state.db_path = _database_path(db_path)
    app.state.sessions = SessionStore()
    app.state.secrets = SecretStore()
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
        expected_category = TOOL_CATEGORIES.get(body.tool)
        if expected_category is None or body.category != expected_category:
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


app = create_app()
