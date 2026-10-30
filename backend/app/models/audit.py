"""
Audit log model.

Append-only — rows are never updated or deleted.
Admin-only read access enforced in the router.

NEVER log: passwords, API keys, session tokens, raw credentials.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, ForeignKey, Index, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.organization import Organization


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """
    Immutable audit record.

    Every security-relevant action must produce an AuditLog entry.
    The metadata field must NEVER contain secrets, passwords, tokens, or
    full scanner output.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        # Per-organization audit view, newest first
        Index("ix_audit_logs_org_timestamp", "organization_id", "timestamp"),
    )

    # NULL actor = system-generated action (e.g., scheduled job)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Dotted action name, e.g. "scan.created", "finding.status_changed"
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    object_type: Mapped[str] = mapped_column(String(100), nullable=False)
    object_id: Mapped[str] = mapped_column(String(36), nullable=False)  # UUID as string

    # Action-specific data — no secrets
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict, nullable=False)

    # Network context
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization | None] = relationship(
        "Organization", back_populates="audit_logs"
    )

    def __repr__(self) -> str:
        return f"<AuditLog action={self.action!r} actor={self.actor_id} ts={self.timestamp}>"
