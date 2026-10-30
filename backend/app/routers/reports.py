"""Report management, session-authenticated and token-gated artifact download endpoints."""

from __future__ import annotations

import re
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.audit import AuditAction, audit_log
from app.core.exceptions import NotFoundError
from app.core.rate_limit import rate_limit_by_ip
from app.core.rbac import OrgAuthContext, require_role
from app.core.security_headers import REPORT_CSP
from app.database import get_db
from app.models.membership import UserRole
from app.models.report import Report
from app.models.user import User
from app.schemas.report import ReportCreateRequest, ReportResponse
from app.services.report_service import ReportService, pdf_export_available

router = APIRouter(tags=["Reports"])

_download_rate_limit = rate_limit_by_ip("report-download", "REPORT_DOWNLOAD_RATE_LIMIT")

# Reports contain sensitive findings: never cache them, never leak their URL
# (which may carry the access token) and never let them run scripts.
_HTML_HEADERS = {
    "Content-Security-Policy": REPORT_CSP,
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}
_PDF_HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}
_UNSAFE_FILENAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


@router.post(
    "/organizations/{organization_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_report(
    organization_id: uuid.UUID,
    req: ReportCreateRequest,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> ReportResponse:
    svc = ReportService(db)
    report = svc.create_report(
        org_id=organization_id,
        scan_id=req.scan_id,
        report_type=req.report_type,
        title=req.title,
        actor=auth_ctx.user,
    )
    return ReportResponse.model_validate(report)


@router.get("/organizations/{organization_id}/reports", response_model=list[ReportResponse])
def list_reports(
    organization_id: uuid.UUID,
    limit: int = Query(100, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> list[ReportResponse]:
    svc = ReportService(db)
    reports = svc.list_reports(organization_id, limit=limit, offset=offset)
    return [ReportResponse.model_validate(r) for r in reports]


@router.get("/organizations/{organization_id}/reports/{report_id}", response_model=ReportResponse)
def get_report(
    organization_id: uuid.UUID,
    report_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> ReportResponse:
    svc = ReportService(db)
    report = svc.get_report(organization_id, report_id)
    return ReportResponse.model_validate(report)


# ── Artifact delivery ─────────────────────────────────────────────────────────

def _ensure_html(svc: ReportService, report: Report) -> Path:
    """Return the report's HTML file, building it only when it is missing."""
    path = svc.html_artifact(report)
    if path is None:
        svc.build_html(report)
        path = svc.html_artifact(report)
    if path is None:
        raise NotFoundError("Report HTML artifact not ready")
    return path


def _ensure_pdf(svc: ReportService, report: Report) -> Path:
    """Return the report's PDF file, building it (and its HTML) only when missing."""
    path = svc.pdf_artifact(report)
    if path is not None:
        return path
    if not pdf_export_available():
        raise NotFoundError("PDF export is not installed on this server")
    _ensure_html(svc, report)
    path = svc.build_pdf(report)
    if path is None:
        raise NotFoundError("PDF artifact could not be generated")
    return path


def _audit_download(
    db: Session, report: Report, fmt: str, via: str, actor: User | None = None
) -> None:
    audit_log(
        db,
        action=AuditAction.REPORT_DOWNLOAD,
        resource_type="report",
        resource_id=str(report.id),
        organization_id=report.organization_id,
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        metadata={"via": via, "format": fmt},
    )


def _html_response(path: Path) -> FileResponse:
    return FileResponse(path, media_type="text/html; charset=utf-8", headers=_HTML_HEADERS)


def _pdf_response(path: Path, report: Report) -> FileResponse:
    safe_title = _UNSAFE_FILENAME_CHARS.sub("_", report.title).strip("._")[:30] or "Report"
    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"Report_{safe_title}.pdf",
        headers=_PDF_HEADERS,
    )


@router.get(
    "/organizations/{organization_id}/reports/{report_id}/html", response_class=FileResponse
)
def view_report_html(
    organization_id: uuid.UUID,
    report_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> FileResponse:
    svc = ReportService(db)
    report = svc.get_report(organization_id, report_id)
    path = _ensure_html(svc, report)
    _audit_download(db, report, "html", "session", auth_ctx.user)
    return _html_response(path)


@router.get("/organizations/{organization_id}/reports/{report_id}/pdf", response_class=FileResponse)
def download_report_pdf_session(
    organization_id: uuid.UUID,
    report_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> FileResponse:
    svc = ReportService(db)
    report = svc.get_report(organization_id, report_id)
    path = _ensure_pdf(svc, report)
    _audit_download(db, report, "pdf", "session", auth_ctx.user)
    return _pdf_response(path, report)


# Token-gated download endpoints (no session required if token is valid)
@router.get(
    "/reports/download/{token}/html",
    response_class=FileResponse,
    dependencies=[Depends(_download_rate_limit)],
)
def download_report_html(
    token: str,
    db: Session = Depends(get_db),
) -> FileResponse:
    svc = ReportService(db)
    report = svc.get_report_by_token(token)
    path = _ensure_html(svc, report)
    _audit_download(db, report, "html", "token")
    return _html_response(path)


@router.get(
    "/reports/download/{token}/pdf",
    response_class=FileResponse,
    dependencies=[Depends(_download_rate_limit)],
)
def download_report_pdf(
    token: str,
    db: Session = Depends(get_db),
) -> FileResponse:
    svc = ReportService(db)
    report = svc.get_report_by_token(token)
    path = _ensure_pdf(svc, report)
    _audit_download(db, report, "pdf", "token")
    return _pdf_response(path, report)
