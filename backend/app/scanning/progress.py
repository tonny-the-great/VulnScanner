"""
Scan progress events for real-time monitoring.

Events are persisted as ScanEvent rows; the SSE endpoint polls them
incrementally, so no separate pub/sub channel is needed.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.models.scan import Scan, ScanEvent


def emit_scan_event(
    db: Session,
    scan_id: uuid.UUID,
    event_type: str,
    payload: dict,
    progress_pct: int | None = None,
    current_stage: str | None = None,
    current_tool: str | None = None,
    current_target: str | None = None,
) -> ScanEvent:
    """
    Persist a ScanEvent in DB, update Scan state fields, and commit.
    """
    event = ScanEvent(
        scan_id=scan_id,
        event_type=event_type,
        payload=payload,
    )
    db.add(event)

    scan = db.get(Scan, scan_id)
    if scan:
        if progress_pct is not None:
            scan.progress_pct = max(0, min(100, progress_pct))
        if current_stage is not None:
            scan.current_stage = current_stage
        if current_tool is not None:
            scan.current_tool = current_tool
        if current_target is not None:
            scan.current_target = current_target

    db.commit()
    return event
