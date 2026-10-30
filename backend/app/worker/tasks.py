"""RQ task handlers for scan execution and report generation."""

from __future__ import annotations

import logging
import uuid

from app.database import get_db_context
from app.scanning.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)


def run_scan_task(scan_id_str: str) -> None:
    """RQ task entrypoint for running a scan."""
    # Imported here: app.services imports this module through scan_service.
    from app.services.scan_reaper import reap_stale_scans

    scan_id = uuid.UUID(scan_id_str)
    logger.info("Worker picked up scan task for scan_id=%s", scan_id)

    with get_db_context() as db:
        # Free concurrency slots held by scans whose worker died. A failure here
        # must not prevent this scan from running.
        try:
            reap_stale_scans(db)
        except Exception:
            logger.exception("Stale scan check failed before scan %s; continuing", scan_id)
            db.rollback()
        orchestrator = ScanOrchestrator(db, scan_id)
        orchestrator.run_scan()


def generate_report_task(report_id_str: str) -> None:
    """RQ task entrypoint for generating report artifacts."""
    from app.services.report_service import ReportService
    report_id = uuid.UUID(report_id_str)
    logger.info("Worker picked up report task for report_id=%s", report_id)

    with get_db_context() as db:
        svc = ReportService(db)
        svc.build_report_files(report_id)
