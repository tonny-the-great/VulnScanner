"""Server-Sent Events (SSE) router for real-time scan progress monitoring."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.exceptions import NotFoundError
from app.core.rbac import OrgAuthContext, require_role
from app.database import SessionLocal, get_db
from app.models.membership import UserRole
from app.models.scan import TERMINAL_SCAN_STATES, Scan, ScanEvent, ScanStatus

router = APIRouter(
    prefix="/organizations/{organization_id}/scans/{scan_id}/events", tags=["Scan Events"]
)

POLL_INTERVAL_SECONDS = 1.0
# Comment frames keep proxies and browsers from closing an idle stream.
KEEPALIVE_INTERVAL_SECONDS = 15.0
_PING_FRAME = b": ping\n\n"


def _event_frame(ev: ScanEvent) -> bytes:
    payload = {
        "id": str(ev.id),
        "event_type": ev.event_type,
        "payload": ev.payload,
        "created_at": ev.created_at.isoformat(),
    }
    return f"event: {ev.event_type}\ndata: {json.dumps(payload)}\n\n".encode()


class _EventCursor:
    """
    Incremental reader of a scan's events.

    Each poll fetches only events created at or after the newest timestamp
    already delivered. Events sharing that timestamp are de-duplicated by id,
    so only the ids at the current last timestamp need to be remembered.

    Assumes events become visible in non-decreasing created_at order (one writer
    per scan at a time, clocks in sync). An event committed later with an
    earlier timestamp, e.g. from a host with a skewed clock, is not delivered
    on an already-open stream; it still appears on replay after a reconnect.
    """

    def __init__(self, scan_id: uuid.UUID) -> None:
        self.scan_id = scan_id
        self.last_ts: datetime | None = None
        self.ids_at_last_ts: set[uuid.UUID] = set()

    def poll(self) -> tuple[ScanStatus | None, list[bytes]]:
        """Return the scan status and any unseen event frames (blocking DB I/O)."""
        # A short-lived session per poll: no connection is held between polls.
        with SessionLocal() as s:
            status = s.scalar(select(Scan.status).where(Scan.id == self.scan_id))
            if status is None:
                return None, []
            stmt = select(ScanEvent).where(ScanEvent.scan_id == self.scan_id)
            if self.last_ts is not None:
                stmt = stmt.where(ScanEvent.created_at >= self.last_ts)
            events = s.scalars(stmt.order_by(ScanEvent.created_at, ScanEvent.id)).all()

            frames = []
            for ev in events:
                if ev.created_at == self.last_ts:
                    if ev.id in self.ids_at_last_ts:
                        continue
                    self.ids_at_last_ts.add(ev.id)
                else:
                    self.last_ts = ev.created_at
                    self.ids_at_last_ts = {ev.id}
                frames.append(_event_frame(ev))
            return status, frames


@router.get("")
async def stream_scan_events(
    organization_id: uuid.UUID,
    scan_id: uuid.UUID,
    request: Request,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
):
    """
    SSE stream of scan progress events.
    Sends existing past events first, then streams new events until terminal state.
    """
    scan = db.get(Scan, scan_id)
    if not scan or scan.organization_id != organization_id:
        raise NotFoundError(f"Scan {scan_id} not found")
    # Yield dependencies stay open until the stream ends; release the request
    # session's connection now so a long-lived stream does not pin a pool slot.
    db.close()

    cursor = _EventCursor(scan_id)

    async def event_generator():
        # Sends past events first, then new ones until the scan reaches a terminal state.
        last_frame_at = time.monotonic()
        while not await request.is_disconnected():
            scan_status, frames = await run_in_threadpool(cursor.poll)
            if scan_status is None:
                break
            for frame in frames:
                yield frame
            if frames:
                last_frame_at = time.monotonic()

            if scan_status in TERMINAL_SCAN_STATES and not frames:
                terminal_payload = {
                    "event_type": "stream_closed",
                    "final_status": scan_status.value,
                }
                yield f"event: done\ndata: {json.dumps(terminal_payload)}\n\n".encode()
                break

            if time.monotonic() - last_frame_at >= KEEPALIVE_INTERVAL_SECONDS:
                yield _PING_FRAME
                last_frame_at = time.monotonic()

            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
