"""
Scan-related models: ScanProfile, Scan, ScanTarget, ScanEvent.

The Scan model implements a strict state machine. State transitions are
enforced in the orchestrator — NOT in the model itself.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.authorization import TargetType
from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.authorization import ScopeAuthorization
    from app.models.organization import Organization


# ── Enums ─────────────────────────────────────────────────────────────────────

class ScanStatus(enum.StrEnum):
    QUEUED = "queued"
    VALIDATING = "validating"
    RUNNING = "running"
    PARSING = "parsing"
    NORMALIZING = "normalizing"
    COMPLETED = "completed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


# Terminal states — no further transitions allowed
TERMINAL_SCAN_STATES: frozenset[ScanStatus] = frozenset({
    ScanStatus.COMPLETED,
    ScanStatus.CANCELLED,
    ScanStatus.FAILED,
    ScanStatus.TIMED_OUT,
})

# Valid state transitions (from → set of allowed tos)
ALLOWED_SCAN_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.QUEUED: frozenset(
        {ScanStatus.VALIDATING, ScanStatus.FAILED, ScanStatus.CANCEL_REQUESTED}
    ),
    ScanStatus.VALIDATING: frozenset(
        {ScanStatus.RUNNING, ScanStatus.FAILED, ScanStatus.CANCEL_REQUESTED}
    ),
    ScanStatus.RUNNING: frozenset(
        {ScanStatus.PARSING, ScanStatus.FAILED, ScanStatus.TIMED_OUT, ScanStatus.CANCEL_REQUESTED}
    ),
    ScanStatus.PARSING: frozenset(
        {ScanStatus.NORMALIZING, ScanStatus.FAILED, ScanStatus.CANCEL_REQUESTED}
    ),
    ScanStatus.NORMALIZING: frozenset(
        {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.TIMED_OUT, ScanStatus.CANCEL_REQUESTED}
    ),
    ScanStatus.CANCEL_REQUESTED: frozenset({ScanStatus.CANCELLED}),
    # Terminal states have no allowed transitions
    ScanStatus.COMPLETED: frozenset(),
    ScanStatus.CANCELLED: frozenset(),
    ScanStatus.FAILED: frozenset(),
    ScanStatus.TIMED_OUT: frozenset(),
}


# ── Models ────────────────────────────────────────────────────────────────────

class ScanProfile(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Server-enforced scan configuration profile.

    Ordinary users never see raw scanner arguments. The backend translates
    a profile into safe, pre-validated command arguments per adapter.
    """

    __tablename__ = "scan_profiles"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,  # NULL = platform-wide default profile
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # UI must show a confirmation dialog before running these
    requires_confirmation: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Requires admin role and explicit acknowledgement in API payload
    is_intrusive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # JSON blob of profile parameters (nmap port ranges, nuclei tags, etc.)
    # This is interpreted server-side only — never passed raw to scanners
    config_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="scan_profiles"
    )

    def __repr__(self) -> str:
        return f"<ScanProfile name={self.name!r} intrusive={self.is_intrusive}>"


class Scan(UUIDPrimaryKeyMixin, Base):
    """
    A single scan execution instance.

    Partial results are always preserved — a scanner failure does not
    destroy results already collected.
    """

    __tablename__ = "scans"
    __table_args__ = (
        # Scan list per organization, newest first
        Index("ix_scans_org_queued_at", "organization_id", "queued_at"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scope_authorizations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scan_profiles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # ── State machine fields ───────────────────────────────────────────────────
    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(ScanStatus, values_callable=lambda obj: [e.value for e in obj]),
        default=ScanStatus.QUEUED,
        nullable=False,
        index=True,
    )
    current_stage: Mapped[str | None] = mapped_column(String(100), nullable=True)
    current_tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    current_target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    progress_pct: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Error message — never expose Python tracebacks here
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # RQ job identifier for cancellation
    rq_job_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Path to raw scanner output directory (UUID-named)
    raw_output_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Denormalized for quick dashboard queries
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # ── Timestamps ────────────────────────────────────────────────────────────
    queued_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    timed_out_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization] = relationship("Organization", back_populates="scans")
    authorization: Mapped[ScopeAuthorization] = relationship(
        "ScopeAuthorization", back_populates="scans"
    )
    targets: Mapped[list[ScanTarget]] = relationship(
        "ScanTarget", back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list[ScanEvent]] = relationship(
        "ScanEvent", back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status.value!r}>"


class ScanTarget(UUIDPrimaryKeyMixin, Base):
    """A validated target within a specific scan."""

    __tablename__ = "scan_targets"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_value: Mapped[str] = mapped_column(String(512), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(
        SAEnum(TargetType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    # Set to True after scope verification succeeds
    scope_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    scan: Mapped[Scan] = relationship("Scan", back_populates="targets")


class ScanEvent(UUIDPrimaryKeyMixin, Base):
    """
    Append-only log of scan progress events.

    These power the SSE stream. Payload must NEVER contain secrets,
    credentials, or raw scanner output.
    """

    __tablename__ = "scan_events"
    __table_args__ = (
        # Event replay and incremental SSE polling, in order
        Index("ix_scan_events_scan_id_created_at", "scan_id", "created_at"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    scan: Mapped[Scan] = relationship("Scan", back_populates="events")
