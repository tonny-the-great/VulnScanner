"""Organization model."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.asset import Asset
    from app.models.audit import AuditLog
    from app.models.authorization import ScopeAuthorization
    from app.models.finding import Finding
    from app.models.membership import OrganizationMembership
    from app.models.report import Report
    from app.models.scan import Scan, ScanProfile


class Organization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Top-level tenant container.

    Every piece of data (scans, findings, assets, authorizations) belongs
    to exactly one organization. Cross-organization access is never permitted.
    """

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Per-org concurrency limit; enforced at scan dispatch time
    max_concurrent_scans: Mapped[int] = mapped_column(Integer, default=2, nullable=False)

    # ── Relationships ─────────────────────────────────────────────────────────
    memberships: Mapped[list[OrganizationMembership]] = relationship(
        "OrganizationMembership",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    authorizations: Mapped[list[ScopeAuthorization]] = relationship(
        "ScopeAuthorization",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    scan_profiles: Mapped[list[ScanProfile]] = relationship(
        "ScanProfile",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    scans: Mapped[list[Scan]] = relationship(
        "Scan",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    assets: Mapped[list[Asset]] = relationship(
        "Asset",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    reports: Mapped[list[Report]] = relationship(
        "Report",
        back_populates="organization",
        cascade="all, delete-orphan",
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        "AuditLog",
        back_populates="organization",
    )

    @validates("slug")
    def validate_slug(self, _key: str, value: str) -> str:
        if not re.match(r"^[a-z0-9][a-z0-9\-]{1,98}[a-z0-9]$", value):
            raise ValueError("Slug must be 3-100 lowercase alphanumeric characters and hyphens")
        return value

    def __repr__(self) -> str:
        return f"<Organization id={self.id} slug={self.slug!r}>"
