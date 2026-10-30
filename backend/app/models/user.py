"""User model."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.membership import OrganizationMembership


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """
    Platform user account.

    Passwords are NEVER stored in plain text. Use the security module
    for hashing (Argon2id) and verification.

    is_superuser grants platform-level access (creating organizations,
    viewing system status). It does NOT imply admin role within any org.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(320),
        unique=True,
        nullable=False,
        index=True,
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Argon2id hash — never expose this in API responses
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Account state
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Brute-force protection
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(), nullable=True
    )

    # ── Relationships ─────────────────────────────────────────────────────────
    memberships: Mapped[list[OrganizationMembership]] = relationship(
        "OrganizationMembership",
        primaryjoin="User.id == OrganizationMembership.user_id",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    @property
    def full_name(self) -> str:
        return self.display_name

    @full_name.setter
    def full_name(self, value: str) -> None:
        self.display_name = value

    # ── Helpers ───────────────────────────────────────────────────────────────
    @property
    def is_locked(self) -> bool:
        """True if the account is locked due to failed login attempts."""
        if self.locked_until is None:
            return False
        # UTCDateTime returns aware values; a value assigned in memory may still be naive.
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=UTC)
        return datetime.now(UTC) < locked_until

    # Failed-login counting and lockout are done with atomic UPDATEs in
    # AuthService (app/services/auth_service.py), not on loaded instances.

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r}>"
