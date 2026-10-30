"""Organization membership model — ties a User to an Organization with a Role."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Enum as SAEnum
from sqlalchemy import ForeignKey, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.user import User


class UserRole(enum.StrEnum):
    """
    Org-level roles. Enforce in service layer — never rely on frontend hiding.

    ADMIN   : full control over the org (users, authorizations, scans, reports)
    ANALYST : create scans, manage findings, generate reports
    VIEWER  : read-only access to findings and reports
    """

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class OrganizationMembership(UUIDPrimaryKeyMixin, Base):
    """Join table between User and Organization with role assignment."""

    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_user"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    joined_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization] = relationship(
        "Organization",
        back_populates="memberships",
    )
    user: Mapped[User] = relationship(
        "User",
        foreign_keys=[user_id],
        back_populates="memberships",
    )

    def __repr__(self) -> str:
        return (
            f"<OrganizationMembership user={self.user_id} "
            f"org={self.organization_id} role={self.role.value!r}>"
        )
