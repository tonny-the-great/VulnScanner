"""Asset and service query service."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.audit import AuditAction, audit_log
from app.core.exceptions import NotFoundError
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.user import User


class AssetService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_assets(
        self,
        org_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0,
        is_active: bool | None = None,
    ) -> list[Asset]:
        stmt = (
            select(Asset)
            .where(Asset.organization_id == org_id)
            .options(selectinload(Asset.services))
        )
        if is_active is not None:
            stmt = stmt.where(Asset.is_active == is_active)
        # Asset.id breaks last_seen ties so pages are stable.
        stmt = stmt.order_by(Asset.last_seen.desc(), Asset.id).limit(limit).offset(offset)
        return list(self.db.scalars(stmt).all())

    def get_asset(self, org_id: uuid.UUID, asset_id: uuid.UUID) -> Asset:
        stmt = (
            select(Asset)
            .where(
                Asset.id == asset_id,
                Asset.organization_id == org_id,
            )
            .options(selectinload(Asset.services))
        )
        asset = self.db.scalars(stmt).first()
        if not asset:
            raise NotFoundError(f"Asset {asset_id} not found")
        return asset

    def _ensure_asset_exists(self, org_id: uuid.UUID, asset_id: uuid.UUID) -> None:
        exists = self.db.scalars(
            select(Asset.id).where(Asset.id == asset_id, Asset.organization_id == org_id)
        ).first()
        if not exists:
            raise NotFoundError(f"Asset {asset_id} not found")

    def get_asset_findings(
        self,
        org_id: uuid.UUID,
        asset_id: uuid.UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        """Findings on one asset, highest priority first (unscored findings last)."""
        self._ensure_asset_exists(org_id, asset_id)
        stmt = (
            select(Finding)
            .where(Finding.organization_id == org_id, Finding.asset_id == asset_id)
            .order_by(Finding.priority_score.desc().nullslast(), Finding.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(stmt).all())

    def update_asset(
        self,
        org_id: uuid.UUID,
        asset_id: uuid.UUID,
        actor: User,
        notes: str | None = None,
        is_active: bool | None = None,
    ) -> Asset:
        """
        Apply analyst edits. None leaves a field unchanged; an empty note clears it.

        Edits never move last_seen (only scans do). The audit entry records which
        fields changed, not the note text.
        """
        asset = self.get_asset(org_id, asset_id)
        changed: list[str] = []
        metadata: dict[str, Any] = {}

        notes_changed = False
        if notes is not None:
            new_notes = notes or None
            if new_notes != asset.notes:
                asset.notes = new_notes
                changed.append("notes")
                notes_changed = True
        if is_active is not None and is_active != asset.is_active:
            asset.is_active = is_active
            changed.append("is_active")
            metadata["is_active"] = is_active

        if not changed:
            return asset

        metadata["changed"] = changed
        metadata["notes_changed"] = notes_changed
        audit_log(
            self.db,
            action=AuditAction.ASSET_UPDATE,
            resource_type="asset",
            resource_id=str(asset.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata=metadata,
            commit=False,
        )
        self.db.commit()
        return self.get_asset(org_id, asset_id)
