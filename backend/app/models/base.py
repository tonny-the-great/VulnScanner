"""
Declarative base and shared mixins for all ORM models.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Uuid
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    """Shared declarative base — all models inherit from this."""
    pass


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """
    Timezone-aware UTC datetime on every backend.

    SQLite has no timezone support and returns naive values even for
    DateTime(timezone=True); this type stores UTC and always returns aware UTC
    datetimes, so comparisons with datetime.now(UTC) are safe everywhere.
    Naive inputs are taken to be UTC. The DDL equals DateTime(timezone=True).
    """

    impl = DateTime
    cache_ok = True

    def __init__(self) -> None:
        super().__init__(timezone=True)

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        return _as_utc(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        return _as_utc(value)


class UUIDPrimaryKeyMixin:
    """UUID primary key — works with SQLite (string storage) and PostgreSQL (native UUID)."""

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        index=True,
    )


class TimestampMixin:
    """Automatic created_at / updated_at timestamps (UTC-aware)."""

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )
