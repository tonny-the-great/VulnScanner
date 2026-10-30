"""Report model."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.organization import Organization


class ReportType(enum.StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"


class Report(UUIDPrimaryKeyMixin, Base):
    """
    Generated report record.

    Reports are served via a signed, time-limited access_token.
    Never use publicly guessable IDs or expose report URLs to unauthenticated users.
    """

    __tablename__ = "reports"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Nullable to support multi-scan comparison reports
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    report_type: Mapped[ReportType] = mapped_column(
        SAEnum(ReportType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    generated_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    generated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Server-side paths — UUID filenames, outside web root
    html_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    pdf_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # HMAC-signed token for time-limited download access
    access_token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    token_expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization] = relationship("Organization", back_populates="reports")
