"""System, health check, and scan profile endpoints."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.redis_client import get_redis_safe, mark_redis_failed
from app.database import get_db
from app.models.scan import ScanProfile
from app.scanning.adapters import ADAPTER_REGISTRY
from app.schemas.scan import ScanProfileResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["System"])


@router.get("/health")
def health_check() -> dict[str, str]:
    """Liveness: the API process is serving requests."""
    return {"status": "ok", "service": "vulnscanner-api"}


@router.get("/health/ready", response_model=None)
def readiness_check(db: Session = Depends(get_db)) -> dict[str, str] | JSONResponse:
    """Readiness: the database answers and, outside development, Redis too.

    Not proxied by nginx; used by container health checks. Responses never
    include error details.
    """
    settings = get_settings()
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("Readiness check: database unavailable (%s)", type(exc).__name__)
        database = "unavailable"

    redis_state = "unavailable"
    conn = get_redis_safe()
    if conn is not None:
        try:
            conn.ping()
            redis_state = "ok"
        except Exception:
            mark_redis_failed()

    # Development and tests may run without Redis (background-thread fallback).
    redis_required = not (settings.is_development or settings.is_testing)
    body = {"status": "ready", "database": database, "redis": redis_state}
    if database != "ok" or (redis_required and redis_state != "ok"):
        body["status"] = "not_ready"
        return JSONResponse(status_code=503, content=body)
    return body


@router.get("/system/scanner-status")
def get_scanner_status() -> dict[str, Any]:
    """Check availability of external scanner binaries on host system."""
    tools = {}
    for name, adapter in ADAPTER_REGISTRY.items():
        # Unauthenticated endpoint: report availability only, not install paths.
        tools[name] = {"available": adapter.is_available()}
    return {
        "status": "operational",
        "tools": tools,
    }


@router.get("/scan-profiles", response_model=list[ScanProfileResponse])
def list_scan_profiles(db: Session = Depends(get_db)) -> list[ScanProfileResponse]:
    # Unauthenticated: platform-wide profiles only, never an organization's own.
    stmt = select(ScanProfile).where(ScanProfile.is_enabled, ScanProfile.organization_id.is_(None))
    profiles = list(db.scalars(stmt).all())
    return [ScanProfileResponse.model_validate(p) for p in profiles]
