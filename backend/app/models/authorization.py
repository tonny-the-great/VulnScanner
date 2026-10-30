"""
Scope authorization and authorized target models.

CRITICAL: No scan may start without a valid, unexpired ScopeAuthorization.
Every target in a scan must be explicitly covered by an AuthorizedTarget entry.
RFC1918 ranges are NOT automatically authorized.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Date,
    ForeignKey,
    String,
    Text,
    Uuid,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.organization import Organization
    from app.models.scan import Scan


class TargetType(enum.StrEnum):
    IPV4 = "ipv4"
    IPV4_CIDR = "ipv4_cidr"
    IPV6 = "ipv6"
    IPV6_CIDR = "ipv6_cidr"
    HOSTNAME = "hostname"
    DOMAIN = "domain"
    URL = "url"


class ScopeAuthorization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Written authorization to scan a set of targets.

    A scan cannot be started unless:
    1. A ScopeAuthorization exists for the organization.
    2. It is not revoked.
    3. Its expiration_date (if set) is in the future at scan start time.
    4. Every scan target is covered by an AuthorizedTarget entry.
    """

    __tablename__ = "scope_authorizations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    signer_name: Mapped[str] = mapped_column(String(255), nullable=False)
    signer_email: Mapped[str] = mapped_column(String(320), nullable=False)
    authorization_date: Mapped[date] = mapped_column(Date, nullable=False)
    expiration_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    # Server-side path with UUID filename — never the original upload filename
    document_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization] = relationship(
        "Organization", back_populates="authorizations"
    )
    authorized_targets: Mapped[list[AuthorizedTarget]] = relationship(
        "AuthorizedTarget",
        back_populates="authorization",
        cascade="all, delete-orphan",
    )
    scans: Mapped[list[Scan]] = relationship(
        "Scan",
        back_populates="authorization",
    )

    @property
    def is_valid(self) -> bool:
        """True if the authorization is currently valid (not revoked, not expired)."""
        if self.is_revoked:
            return False
        if self.expiration_date and self.expiration_date < datetime.now(UTC).date():
            return False
        return True

    def __repr__(self) -> str:
        return f"<ScopeAuthorization id={self.id} title={self.title!r} valid={self.is_valid}>"


class AuthorizedTarget(UUIDPrimaryKeyMixin, Base):
    """
    A single authorized scanning target within a ScopeAuthorization.

    Stored in canonical, validated form. Target validation happens at
    creation time — the raw user input is never stored.
    """

    __tablename__ = "authorized_targets"

    authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scope_authorizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_type: Mapped[TargetType] = mapped_column(
        SAEnum(TargetType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    # Stored in canonical form (e.g., IP normalized, CIDR compressed, hostname lowercased)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    authorization: Mapped[ScopeAuthorization] = relationship(
        "ScopeAuthorization", back_populates="authorized_targets"
    )

    def __repr__(self) -> str:
        return f"<AuthorizedTarget {self.target_type.value}:{self.value!r}>"
