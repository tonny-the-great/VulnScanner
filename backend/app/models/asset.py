"""Asset and Service models — first-class objects, not raw scanner artefacts."""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Integer,
    String,
    Text,
    Uuid,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UTCDateTime, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.organization import Organization


class AssetType(enum.StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    HOSTNAME = "hostname"
    DOMAIN = "domain"
    WEBAPP = "webapp"


class ServiceState(enum.StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class ServiceProtocol(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"


class Asset(UUIDPrimaryKeyMixin, Base):
    """
    A discovered host, endpoint, or web application.

    Assets are normalized before findings are associated with them.
    The same physical host may appear as both an IP and hostname —
    the AssetNormalizer (Phase 3) handles deduplication.
    """

    __tablename__ = "assets"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_type: Mapped[AssetType] = mapped_column(
        SAEnum(AssetType, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )

    # At least one of these should be non-null
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    domain: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # OS fingerprint (best-effort from Nmap)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_confidence: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0–100

    # Lifecycle. last_seen is set explicitly when a scan observes the asset;
    # editing the asset (e.g. its notes) must not move it.
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
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Which scanner/mechanism first discovered this asset
    discovery_source: Mapped[str] = mapped_column(String(100), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Relationships ─────────────────────────────────────────────────────────
    organization: Mapped[Organization] = relationship("Organization", back_populates="assets")
    services: Mapped[list[Service]] = relationship(
        "Service", back_populates="asset", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="asset")

    def __repr__(self) -> str:
        identifier = self.ip_address or self.hostname or self.domain or str(self.id)
        return f"<Asset {self.asset_type.value}:{identifier!r}>"


class Service(UUIDPrimaryKeyMixin, Base):
    """A network service discovered on an Asset."""

    __tablename__ = "services"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    protocol: Mapped[ServiceProtocol] = mapped_column(
        SAEnum(ServiceProtocol, values_callable=lambda obj: [e.value for e in obj]),
        nullable=False,
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[ServiceState] = mapped_column(
        SAEnum(ServiceState, values_callable=lambda obj: [e.value for e in obj]),
        default=ServiceState.OPEN,
        nullable=False,
    )
    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    # Set explicitly by scans, like Asset.last_seen
    last_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="services")
    findings: Mapped[list[Finding]] = relationship("Finding", back_populates="service")

    def __repr__(self) -> str:
        return f"<Service {self.protocol.value}/{self.port} {self.service_name or '?'}>"
