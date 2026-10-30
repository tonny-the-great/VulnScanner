"""
Asset normalizer and deduplication manager.

Reconciles raw scanner asset and service discoveries with existing
Asset and Service records in the database.

The normalizer never commits: it only flushes, so the caller persists the
assets together with the findings that reference them (or rolls both back).
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.models.asset import Asset, Service
from app.scanning.adapters.base import RawDiscoveredAsset, RawDiscoveredService

logger = logging.getLogger(__name__)

# Upper bound on bound parameters per IN (...) clause.
LOOKUP_CHUNK_SIZE = 500


def _chunks(values: list[str], size: int = LOOKUP_CHUNK_SIZE) -> Iterable[list[str]]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _hostname_key(hostname: str | None) -> str | None:
    """Hostnames are case-insensitive (RFC 4343)."""
    if not hostname:
        return None
    key = hostname.strip().lower()
    return key or None


class AssetNormalizer:
    """Reconciles discovered assets and services into persistent DB records."""

    def __init__(self, db: Session, organization_id: uuid.UUID) -> None:
        self.db = db
        self.organization_id = organization_id

    def upsert_discovered_assets(
        self,
        raw_assets: list[RawDiscoveredAsset],
        source_tool: str,
    ) -> list[Asset]:
        """
        Merge raw discovered assets and their services into the session.

        Returns a list aligned 1:1 with ``raw_assets``: element ``i`` is the
        Asset for ``raw_assets[i]``. Raw assets describing the same host (same
        IP address, or same hostname ignoring case) map to the same Asset
        object. Every returned asset has an id, and its new services are
        already in ``asset.services``, so callers need no further loads.

        Existing assets are matched by IP address first, then by hostname. A
        hostname match never changes the stored IP address (it is part of the
        finding fingerprint).

        Ends with a flush and never commits; the caller owns the transaction.
        """
        now = datetime.now(UTC)
        by_ip, by_hostname = self._preload_existing(raw_assets)
        persisted_assets: list[Asset] = []

        for raw in raw_assets:
            asset = self._match(raw, by_ip, by_hostname)

            if asset is not None:
                # Update existing asset
                asset.last_seen = now
                asset.is_active = True
                if raw.os_name and (
                    not asset.os_confidence
                    or (raw.os_confidence and raw.os_confidence > asset.os_confidence)
                ):
                    asset.os_name = raw.os_name
                    asset.os_version = raw.os_version
                    asset.os_confidence = raw.os_confidence
            else:
                # Create new asset; the id is assigned now so inserts batch at flush.
                asset = Asset(
                    id=uuid.uuid4(),
                    organization_id=self.organization_id,
                    asset_type=raw.asset_type,
                    ip_address=raw.ip_address,
                    # Stored trimmed, so the case-insensitive SQL preload
                    # (lower(hostname) IN keys) matches it on later scans.
                    hostname=(raw.hostname.strip() or None) if raw.hostname else raw.hostname,
                    domain=raw.domain,
                    os_name=raw.os_name,
                    os_version=raw.os_version,
                    os_confidence=raw.os_confidence,
                    first_seen=now,
                    last_seen=now,
                    is_active=True,
                    discovery_source=source_tool,
                    services=[],
                )
                self.db.add(asset)

            # Index by the asset's own identifiers, so later duplicates in the
            # batch resolve to this object.
            if asset.ip_address:
                by_ip.setdefault(asset.ip_address, asset)
            host_key = _hostname_key(asset.hostname)
            if host_key:
                by_hostname.setdefault(host_key, asset)

            self._reconcile_services(asset, raw.services, now)
            persisted_assets.append(asset)

        self.db.flush()
        return persisted_assets

    def _preload_existing(
        self, raw_assets: list[RawDiscoveredAsset]
    ) -> tuple[dict[str, Asset], dict[str, Asset]]:
        """Load every candidate asset (with its services) in one query per chunk."""
        ips = sorted({raw.ip_address for raw in raw_assets if raw.ip_address})
        hostnames = sorted({key for raw in raw_assets if (key := _hostname_key(raw.hostname))})
        by_ip: dict[str, Asset] = {}
        by_hostname: dict[str, Asset] = {}
        if not ips and not hostnames:
            return by_ip, by_hostname

        ip_chunks = list(_chunks(ips))
        host_chunks = list(_chunks(hostnames))
        for index in range(max(len(ip_chunks), len(host_chunks))):
            conditions = []
            if index < len(ip_chunks):
                conditions.append(Asset.ip_address.in_(ip_chunks[index]))
            if index < len(host_chunks):
                conditions.append(func.lower(Asset.hostname).in_(host_chunks[index]))
            stmt = (
                select(Asset)
                .where(Asset.organization_id == self.organization_id, or_(*conditions))
                .options(selectinload(Asset.services))
                # Deterministic choice when several stored assets share an identifier.
                .order_by(Asset.first_seen, Asset.id)
            )
            for asset in self.db.scalars(stmt):
                if asset.ip_address:
                    by_ip.setdefault(asset.ip_address, asset)
                host_key = _hostname_key(asset.hostname)
                if host_key:
                    by_hostname.setdefault(host_key, asset)
        return by_ip, by_hostname

    @staticmethod
    def _match(
        raw: RawDiscoveredAsset,
        by_ip: dict[str, Asset],
        by_hostname: dict[str, Asset],
    ) -> Asset | None:
        """Find the matching asset by IP address, then by hostname."""
        if raw.ip_address and raw.ip_address in by_ip:
            return by_ip[raw.ip_address]
        host_key = _hostname_key(raw.hostname)
        if host_key and host_key in by_hostname:
            return by_hostname[host_key]
        return None

    def _reconcile_services(
        self,
        asset: Asset,
        raw_services: list[RawDiscoveredService],
        now: datetime,
    ) -> None:
        """Upsert services for an asset (asset.services is already loaded)."""
        existing_services = {(s.protocol, s.port): s for s in asset.services}

        for raw_srv in raw_services:
            key = (raw_srv.protocol, raw_srv.port)
            if key in existing_services:
                srv = existing_services[key]
                srv.last_seen = now
                srv.state = raw_srv.state
                if raw_srv.service_name:
                    srv.service_name = raw_srv.service_name
                if raw_srv.product:
                    srv.product = raw_srv.product
                if raw_srv.version:
                    srv.version = raw_srv.version
                if raw_srv.extra_info:
                    srv.extra_info = raw_srv.extra_info
            else:
                new_srv = Service(
                    id=uuid.uuid4(),
                    protocol=raw_srv.protocol,
                    port=raw_srv.port,
                    service_name=raw_srv.service_name,
                    product=raw_srv.product,
                    version=raw_srv.version,
                    extra_info=raw_srv.extra_info,
                    state=raw_srv.state,
                    first_seen=now,
                    last_seen=now,
                )
                # Appending sets asset_id at flush and keeps the collection current.
                asset.services.append(new_srv)
                existing_services[key] = new_srv
