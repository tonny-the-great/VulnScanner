"""Report generation and management service."""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import ColumnElement, and_, case, func, or_, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.audit import AuditAction, audit_log
from app.core.exceptions import AuthenticationError, NotFoundError
from app.models.asset import Asset
from app.models.finding import (
    Finding,
    FindingConfidence,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    ScanFinding,
    ScanFindingSnapshot,
    finding_seen_in_scan,
)
from app.models.organization import Organization
from app.models.report import Report, ReportType
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.worker.queues import enqueue_job
from app.worker.tasks import generate_report_task

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "reporting" / "templates"

# Compiled templates are cached by the environment, so it is built once per process.
_JINJA_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)

_EXECUTIVE_TOP_FINDINGS = 10
_TOKEN_LIFETIME = timedelta(hours=24)


def load_weasyprint() -> ModuleType | None:
    """
    Return the WeasyPrint module, or None when PDF export is unavailable.

    Resolved at call time (not with importlib.util.find_spec) so a missing or
    broken installation, including its native libraries, simply disables PDF export.
    """
    try:
        import weasyprint
    except Exception:
        return None
    return weasyprint


def pdf_export_available() -> bool:
    return load_weasyprint() is not None


def _deny_url_fetch(url: str, *args: Any, **kwargs: Any) -> dict:
    # Reports are self-contained; never let PDF rendering reach the network or disk.
    raise ValueError(f"Report rendering does not load external resources: {url[:100]}")


def _reports_dir() -> Path:
    return Path(get_settings().upload_dir) / "reports"


def _write_atomically(path: Path, write: Any) -> None:
    """Write via a temporary file so concurrent downloads never see a partial artifact."""
    tmp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        write(tmp_path)
        os.replace(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _existing_artifact(path_str: str | None) -> Path | None:
    """Return the artifact path when it exists inside the reports directory."""
    if not path_str:
        return None
    try:
        path = Path(path_str).resolve()
        reports_dir = _reports_dir().resolve()
    except OSError:
        return None
    if reports_dir not in path.parents or not path.is_file():
        return None
    return path


class ReportService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.jinja_env = _JINJA_ENV

    def create_report(
        self,
        org_id: uuid.UUID,
        scan_id: uuid.UUID | None,
        report_type: ReportType,
        title: str,
        actor: User,
    ) -> Report:
        """Create a report record, issue time-limited access token and enqueue generation task."""
        if scan_id:
            scan = self.db.get(Scan, scan_id)
            if not scan or scan.organization_id != org_id:
                raise NotFoundError("Scan not found for this organization")

        report = Report(
            organization_id=org_id,
            scan_id=scan_id,
            report_type=report_type,
            title=title.strip(),
            generated_by=actor.id,
            access_token=secrets.token_urlsafe(32),
            token_expires_at=datetime.now(UTC) + _TOKEN_LIFETIME,
        )
        self.db.add(report)
        self.db.flush()
        audit_log(
            self.db,
            action=AuditAction.REPORT_GENERATE,
            resource_type="report",
            resource_id=str(report.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={"title": report.title, "report_type": report.report_type.value},
            commit=False,
        )
        self.db.commit()
        self.db.refresh(report)

        # Enqueue only after the commit, so the worker always finds the record.
        # Downloads build the report lazily if queueing fails.
        try:
            enqueue_job("reports", generate_report_task, str(report.id))
        except Exception:
            logger.warning(
                "Report %s was not queued; it will be built on first download", report.id
            )

        return report

    def list_reports(self, org_id: uuid.UUID, limit: int = 100, offset: int = 0) -> list[Report]:
        stmt = (
            select(Report)
            .where(Report.organization_id == org_id)
            .order_by(Report.generated_at.desc(), Report.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(stmt).all())

    def get_report(self, org_id: uuid.UUID, report_id: uuid.UUID) -> Report:
        stmt = select(Report).where(
            Report.id == report_id,
            Report.organization_id == org_id,
        )
        report = self.db.scalars(stmt).first()
        if not report:
            raise NotFoundError(f"Report {report_id} not found")
        return report

    def get_report_by_token(self, token: str) -> Report:
        """Lookup report by time-limited access token."""
        stmt = select(Report).where(Report.access_token == token)
        report = self.db.scalars(stmt).first()
        if not report:
            raise AuthenticationError("Invalid or nonexistent report access token")
        if report.token_expires_at <= datetime.now(UTC):
            raise AuthenticationError("Report access token has expired")
        return report

    # ── Artifacts ─────────────────────────────────────────────────────────────

    @staticmethod
    def html_artifact(report: Report) -> Path | None:
        """The report's HTML file, if it has been built and is still on disk."""
        return _existing_artifact(report.html_path)

    @staticmethod
    def pdf_artifact(report: Report) -> Path | None:
        """The report's PDF file, if it has been built and is still on disk."""
        return _existing_artifact(report.pdf_path)

    def build_report_files(self, report_id: uuid.UUID) -> None:
        """Generate the HTML file and, when WeasyPrint is installed, the PDF for a report."""
        report = self.db.get(Report, report_id)
        if not report:
            return
        self.build_html(report)
        self.build_pdf(report)

    def build_html(self, report: Report) -> Path:
        """Render the report HTML, write it to disk and commit its path immediately."""
        reports_dir = _reports_dir()
        reports_dir.mkdir(parents=True, exist_ok=True)

        html_content = self._render_html(report)
        html_path = reports_dir / f"{report.id}.html"
        _write_atomically(html_path, lambda tmp: tmp.write_text(html_content, encoding="utf-8"))

        report.html_path = str(html_path)
        self.db.commit()
        return html_path

    def build_pdf(self, report: Report) -> Path | None:
        """Render the PDF from the existing HTML file; returns None when unavailable."""
        weasyprint = load_weasyprint()
        if weasyprint is None:
            logger.info("PDF export skipped for report %s: WeasyPrint is not installed", report.id)
            return None
        html_path = self.html_artifact(report)
        if html_path is None:
            logger.info("PDF export skipped for report %s: HTML has not been built", report.id)
            return None

        pdf_path = html_path.with_suffix(".pdf")
        try:
            html_content = html_path.read_text(encoding="utf-8")
            document = weasyprint.HTML(string=html_content, url_fetcher=_deny_url_fetch)
            _write_atomically(pdf_path, lambda tmp: document.write_pdf(str(tmp)))
        except Exception as exc:
            logger.info("PDF export failed for report %s: %s", report.id, exc)
            return None

        report.pdf_path = str(pdf_path)
        self.db.commit()
        return pdf_path

    # ── Rendering ─────────────────────────────────────────────────────────────

    def _render_html(self, report: Report) -> str:
        org_id = report.organization_id
        scan_id = report.scan_id

        findings_filter: ColumnElement[bool] = Finding.organization_id == org_id
        if scan_id:
            findings_filter = findings_filter & finding_seen_in_scan(scan_id)

        # An organization overview must distinguish missing assessment coverage
        # from completed assessments that recorded no findings.
        scan_counts_query = (
            select(Scan.status, func.count(Scan.id))
            .where(Scan.organization_id == org_id)
            .group_by(Scan.status)
        )
        if scan_id:
            scan_counts_query = scan_counts_query.where(Scan.id == scan_id)
        scan_counts = dict(self.db.execute(scan_counts_query).all())

        scan = self.db.get(Scan, scan_id) if scan_id else None
        context: dict[str, Any] = {
            "report": report,
            "scan": scan,
            "org": self.db.get(Organization, org_id),
            "scan_count": sum(scan_counts.values()),
            "completed_scan_count": scan_counts.get(ScanStatus.COMPLETED, 0),
        }

        if report.report_type == ReportType.EXECUTIVE:
            template_name = "executive.html"
            context.update(self._executive_context(findings_filter, org_id, scan_id))
        else:
            template_name = "technical.html"
            context.update(self._technical_context(findings_filter, scan))

        return self.jinja_env.get_template(template_name).render(**context)

    def _executive_context(
        self,
        findings_filter: ColumnElement[bool],
        org_id: uuid.UUID,
        scan_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        if scan_id:
            return self._scan_executive_context(findings_filter, scan_id)
        total_findings = self.db.scalar(
            select(func.count()).select_from(Finding).where(findings_filter)
        ) or 0
        critical_high_count = self.db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                findings_filter,
                Finding.severity.in_((FindingSeverity.CRITICAL, FindingSeverity.HIGH)),
            )
        ) or 0
        top_findings = list(self.db.scalars(
            select(Finding)
            .where(findings_filter)
            .order_by(Finding.priority_score.desc().nullslast(), Finding.id)
            .limit(_EXECUTIVE_TOP_FINDINGS)
        ).all())

        asset_count_query = (
            select(func.count()).select_from(Asset).where(Asset.organization_id == org_id)
        )
        asset_count = self.db.scalar(asset_count_query) or 0

        return {
            "total_findings": total_findings,
            "critical_high_count": critical_high_count,
            "top_findings": top_findings,
            "asset_count": asset_count,
        }

    @staticmethod
    def _snapshot_condition(scan_id: uuid.UUID) -> ColumnElement[bool]:
        return and_(
            ScanFindingSnapshot.finding_id == Finding.id,
            ScanFindingSnapshot.scan_id == scan_id,
        )

    @staticmethod
    def _report_finding(
        finding: Finding, snapshot: ScanFindingSnapshot | None,
    ) -> SimpleNamespace:
        """Render detached values; never overwrite the live identity-map object."""
        fields = (
            "title", "description", "source_tool", "scanner_reference", "fingerprint",
            "confidence", "status", "cve_ids", "cwe_ids", "cvss_score", "cvss_vector",
        )
        values = {field: getattr(finding, field) for field in fields}
        if snapshot is not None:
            values.update({field: snapshot.data[field] for field in fields})
            values["confidence"] = FindingConfidence(values["confidence"])
            values["status"] = FindingStatus(values["status"])
        return SimpleNamespace(
            **values,
            id=finding.id,
            severity=snapshot.severity if snapshot else finding.severity,
            priority_score=snapshot.priority_score if snapshot else finding.priority_score,
            asset_id=snapshot.asset_id if snapshot else finding.asset_id,
            snapshot_available=snapshot is not None,
            # Guidance is separate from scanner observations and labelled current.
            llm_remediation=finding.llm_remediation,
        )

    def _scan_executive_context(
        self, findings_filter: ColumnElement[bool], scan_id: uuid.UUID,
    ) -> dict[str, Any]:
        has_snapshot = ScanFindingSnapshot.scan_id.is_not(None)
        severity = case((has_snapshot, ScanFindingSnapshot.severity), else_=Finding.severity)
        priority = case(
            (has_snapshot, ScanFindingSnapshot.priority_score), else_=Finding.priority_score,
        )
        asset_id = case((has_snapshot, ScanFindingSnapshot.asset_id), else_=Finding.asset_id)
        summary = self.db.execute(
            select(
                func.count(Finding.id),
                func.sum(case((severity.in_((FindingSeverity.CRITICAL, FindingSeverity.HIGH)), 1),
                              else_=0)),
                func.count(func.distinct(asset_id)),
                func.sum(case((has_snapshot, 0), else_=1)),
            )
            .select_from(Finding)
            .outerjoin(ScanFindingSnapshot, self._snapshot_condition(scan_id))
            .where(findings_filter)
        ).one()
        top_rows = self.db.execute(
            select(Finding, ScanFindingSnapshot)
            .outerjoin(ScanFindingSnapshot, self._snapshot_condition(scan_id))
            .where(findings_filter)
            .order_by(priority.desc().nullslast(), Finding.id)
            .limit(_EXECUTIVE_TOP_FINDINGS)
        ).all()
        return {
            "total_findings": summary[0],
            "critical_high_count": summary[1] or 0,
            "asset_count": summary[2],
            "missing_snapshot_count": summary[3] or 0,
            "top_findings": [self._report_finding(f, snapshot) for f, snapshot in top_rows],
        }

    def _technical_context(
        self,
        findings_filter: ColumnElement[bool],
        scan: Scan | None,
    ) -> dict[str, Any]:
        if scan is not None:
            priority = case(
                (ScanFindingSnapshot.scan_id.is_not(None), ScanFindingSnapshot.priority_score),
                else_=Finding.priority_score,
            )
            rows = self.db.execute(
                select(Finding, ScanFindingSnapshot)
                .outerjoin(ScanFindingSnapshot, self._snapshot_condition(scan.id))
                .where(findings_filter)
                .order_by(priority.desc().nullslast(), Finding.id)
            ).all()
            missing_count = sum(snapshot is None for _, snapshot in rows)
            legacy_filter = findings_filter & ~Finding.id.in_(
                select(ScanFindingSnapshot.finding_id)
                .where(ScanFindingSnapshot.scan_id == scan.id)
            )
            evidence: dict[uuid.UUID, Any] = (
                self._evidence_by_finding(legacy_filter, scan) if missing_count else {}
            )
            for finding, snapshot in rows:
                if snapshot is not None:
                    evidence[finding.id] = [
                        SimpleNamespace(**item) for item in snapshot.data.get("evidence", [])
                    ]
            return {
                "findings": [self._report_finding(f, snapshot) for f, snapshot in rows],
                "total_findings": len(rows),
                "evidence_by_finding": evidence,
                "missing_snapshot_count": missing_count,
            }
        findings = list(self.db.scalars(
            select(Finding)
            .where(findings_filter)
            .order_by(Finding.priority_score.desc().nullslast())
        ).all())
        evidence_by_finding = self._evidence_by_finding(findings_filter, scan) if findings else {}
        return {
            "findings": findings,
            "total_findings": len(findings),
            "evidence_by_finding": evidence_by_finding,
        }

    def _evidence_by_finding(
        self,
        findings_filter: ColumnElement[bool],
        scan: Scan | None,
    ) -> dict[uuid.UUID, list[FindingEvidence]]:
        """
        Evidence to show per in-scope finding, loaded in one statement.

        Evidence is resolved per (finding, evidence type), mirroring the
        deduplicator, which skips each item that repeats the newest stored
        observation of the same type. A scan may therefore store some types for
        a finding and not others.

        - Organization reports show the newest observation of each type: every
          row sharing the newest collected_at (rank(), not row_number(), since
          one scan stores several items of a type with the same timestamp).
        - Scan reports show, per type, the scan's own rows when it stored any.
          Otherwise they show the newest observation of that type as of the
          scan: rows collected no later than the scan's sighting of the finding
          (scan_findings.seen_at, the same instant its own evidence would carry),
          or, for scans recorded before scan_findings existed, no later than the
          scan finished. Evidence collected by later scans is never shown.

        Not covered: when a scan stores some items of a type but repeats others
        (it saw {A, B}, A repeated the newest stored row, so only B was stored),
        the report shows only B. Which earlier items the scan repeated is not
        recorded, and showing all earlier items would claim evidence the scan
        may not have seen.
        """
        in_scope_ids = select(Finding.id).where(findings_filter)
        rank = func.rank().over(
            partition_by=(FindingEvidence.finding_id, FindingEvidence.evidence_type),
            order_by=FindingEvidence.collected_at.desc(),
        ).label("rank")
        candidates = select(FindingEvidence.id.label("evidence_id"), rank).where(
            FindingEvidence.finding_id.in_(in_scope_ids)
        )
        scan_id = scan.id if scan is not None else None
        if scan is not None:
            # Rank only what existed when this scan saw the finding.
            candidates = candidates.outerjoin(
                ScanFinding,
                and_(
                    ScanFinding.finding_id == FindingEvidence.finding_id,
                    ScanFinding.scan_id == scan.id,
                ),
            )
            unrecorded_sighting = ScanFinding.seen_at.is_(None)
            finished_at = scan.completed_at or scan.timed_out_at or scan.cancelled_at
            if finished_at is not None:
                unrecorded_sighting = and_(
                    unrecorded_sighting, FindingEvidence.collected_at <= finished_at
                )
            candidates = candidates.where(or_(
                FindingEvidence.scan_id == scan.id,
                FindingEvidence.collected_at <= ScanFinding.seen_at,
                unrecorded_sighting,
            ))
        ranked = candidates.subquery()
        newest = ranked.c.rank == 1
        stmt = (
            select(FindingEvidence, ranked.c.rank)
            .join(ranked, ranked.c.evidence_id == FindingEvidence.id)
            .where(or_(newest, FindingEvidence.scan_id == scan_id) if scan_id else newest)
            .order_by(FindingEvidence.collected_at, FindingEvidence.id)
        )
        rows = self.db.execute(stmt).all()

        types_with_own_rows = {
            (evidence.finding_id, evidence.evidence_type)
            for evidence, _ in rows
            if scan_id is not None and evidence.scan_id == scan_id
        }
        evidence_by_finding: dict[uuid.UUID, list[FindingEvidence]] = defaultdict(list)
        for evidence, row_rank in rows:
            if (evidence.finding_id, evidence.evidence_type) in types_with_own_rows:
                keep = evidence.scan_id == scan_id
            else:
                keep = row_rank == 1
            if keep:
                evidence_by_finding[evidence.finding_id].append(evidence)
        return dict(evidence_by_finding)
