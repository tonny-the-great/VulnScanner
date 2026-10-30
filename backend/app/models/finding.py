"""
Finding and related models.

CRITICAL DESIGN: A Finding is NOT recreated on every scan.
Findings persist via stable fingerprint-based upserts. The fingerprint
algorithm is documented in app/scanning/normalization/fingerprint.py.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    Boolean,
    ColumnElement,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    Uuid,
    or_,
    select,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.asset import Asset, Service
    from app.models.organization import Organization


# ── Enums ─────────────────────────────────────────────────────────────────────

class FindingSeverity(enum.StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(enum.StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class FindingConfidence(enum.StrEnum):
    """
    Confidence levels for findings.

    CONFIRMED  : Active verification succeeded (e.g., Nuclei exploit response,
                 testssl protocol negotiation confirmed)
    LIKELY     : Version matches known vulnerable range with high-confidence matcher
    UNVERIFIED : Banner/version-only; no active confirmation
    """

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    UNVERIFIED = "unverified"


# ── Models ────────────────────────────────────────────────────────────────────

class Finding(UUIDPrimaryKeyMixin, Base):
    """
    A normalized, deduplicated vulnerability finding.

    Persists across scans. The fingerprint field uniquely identifies
    a finding for a given (org, asset, service, vuln_id, title_slug) tuple.
    See FingerprintEngine for the exact algorithm.

    Three layers — kept separate:
      1. source_tool + scanner_reference → what the scanner detected
      2. severity + cvss + priority_score → how serious it is
      3. llm_remediation → what to do about it
    """

    __tablename__ = "findings"
    __table_args__ = (
        # Default finding list order: organization, highest priority first
        Index("ix_findings_org_priority", "organization_id", "priority_score"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    service_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("services.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Layer 1: What the scanner detected
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner_reference: Mapped[str | None] = mapped_column(String(512), nullable=True)
    confidence: Mapped[FindingConfidence] = mapped_column(
        SAEnum(FindingConfidence, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )

    # CVE/CWE stored as JSON arrays for SQLite/Postgres cross-compatibility
    # PostgreSQL upgrade path: migrate to ARRAY type
    cve_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    cwe_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    # Layer 2: How serious it is
    severity: Mapped[FindingSeverity] = mapped_column(
        SAEnum(FindingSeverity, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
        index=True,
    )
    # Original CVSS score — NEVER modified after import
    cvss_score: Mapped[float | None] = mapped_column(Numeric(4, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # Platform-derived priority (labeled clearly — not CVSS)
    priority_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)

    # Deduplication fingerprint — see FingerprintEngine for algorithm
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Status & assignment
    status: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, values_callable=lambda obj: [e.value for e in obj]),
        default=FindingStatus.OPEN,
        nullable=False,
        index=True,
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Lifecycle timestamps
    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    last_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    fixed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    accepted_risk_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    accepted_risk_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Scan references (full per-scan history lives in scan_findings)
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Layer 3: LLM remediation (validated against RemediationSchema)
    # Null = not yet generated. llm_remediation_failed = True means generation failed.
    llm_remediation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    llm_remediation_cached_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    llm_remediation_failed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization] = relationship("Organization", back_populates="findings")
    asset: Mapped[Asset | None] = relationship("Asset", back_populates="findings")
    service: Mapped[Service | None] = relationship("Service", back_populates="findings")
    evidence: Mapped[list[FindingEvidence]] = relationship(
        "FindingEvidence", back_populates="finding", cascade="all, delete-orphan"
    )
    remediation_notes: Mapped[list[RemediationNote]] = relationship(
        "RemediationNote", back_populates="finding", cascade="all, delete-orphan"
    )
    assignments: Mapped[list[FindingAssignment]] = relationship(
        "FindingAssignment", back_populates="finding", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Finding id={self.id} severity={self.severity.value!r} "
            f"status={self.status.value!r} fp={self.fingerprint[:8]}>"
        )


class FindingEvidence(UUIDPrimaryKeyMixin, Base):
    """
    Raw scanner evidence associated with a finding.

    NEVER destroyed during normalization. Treated as untrusted data —
    must be escaped before rendering in HTML/reports.
    """

    __tablename__ = "finding_evidence"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    evidence_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # Raw content — treated as untrusted, escaped on all renders
    content: Mapped[str] = mapped_column(Text, nullable=False)
    collected_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    finding: Mapped[Finding] = relationship("Finding", back_populates="evidence")


class RemediationNote(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Human-authored note on a finding's remediation progress."""

    __tablename__ = "remediation_notes"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    note: Mapped[str] = mapped_column(Text, nullable=False)
    status_at_time: Mapped[FindingStatus] = mapped_column(
        SAEnum(FindingStatus, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )

    finding: Mapped[Finding] = relationship("Finding", back_populates="remediation_notes")


class FindingAssignment(UUIDPrimaryKeyMixin, Base):
    """Assignment record — only one active assignment per finding at a time."""

    __tablename__ = "finding_assignments"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assigned_to: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    assigned_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    is_current: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)

    finding: Mapped[Finding] = relationship("Finding", back_populates="assignments")


class ScanFinding(Base):
    """
    One row per (scan, finding) sighting: the per-scan finding history.

    A Finding only remembers its first and last scan; this table records every
    scan that observed it, so reports and scan comparisons stay accurate for
    scans in between.
    """

    __tablename__ = "scan_findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        primary_key=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("findings.id", ondelete="CASCADE"),
        primary_key=True,
        index=True,
    )
    seen_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )


class ScanFindingSnapshot(Base):
    """Finding state and complete evidence captured when a scan observes it.

    A separate, additive table lets existing installations create it without
    altering scan_findings. Older sightings deliberately have no snapshot:
    their historical values cannot be reconstructed from the live finding.
    """

    __tablename__ = "scan_finding_snapshots"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True,
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True,
    )
    captured_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    severity: Mapped[FindingSeverity] = mapped_column(
        SAEnum(FindingSeverity, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    priority_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    # No asset FK: removing a live asset must not rewrite historical asset counts.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=False)


def finding_seen_in_scan(scan_id: uuid.UUID) -> ColumnElement[bool]:
    """
    Filter for findings observed by the given scan.

    scan_findings is authoritative for scans recorded after that table existed.
    The first/last scan references and evidence rows are a fallback for scans
    recorded before it, which have no scan_findings rows.
    """
    sightings = select(ScanFinding.finding_id).where(ScanFinding.scan_id == scan_id)
    evidence = select(FindingEvidence.finding_id).where(FindingEvidence.scan_id == scan_id)
    return or_(
        Finding.id.in_(sightings),
        Finding.first_seen_scan_id == scan_id,
        Finding.last_seen_scan_id == scan_id,
        Finding.id.in_(evidence),
    )
