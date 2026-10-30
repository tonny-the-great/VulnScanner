"""Organization and membership service."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.audit import AuditAction, audit_log
from app.core.exceptions import ConflictError, NotFoundError, PermissionDeniedError
from app.models.membership import OrganizationMembership, UserRole
from app.models.organization import Organization
from app.models.user import User


class OrganizationService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def _ensure_name_available(self, name: str, exclude_id: uuid.UUID | None = None) -> None:
        stmt = select(Organization.id).where(Organization.name == name)
        if exclude_id is not None:
            stmt = stmt.where(Organization.id != exclude_id)
        if self.db.scalars(stmt.limit(1)).first() is not None:
            raise ConflictError(f"Organization name '{name}' is already taken")

    def create_organization(
        self,
        name: str,
        slug: str,
        actor: User,
        max_concurrent_scans: int = 2,
    ) -> Organization:
        """Create a new organization and assign actor as first ADMIN member."""
        if get_settings().ORG_CREATION == "superuser" and not actor.is_superuser:
            raise PermissionDeniedError("Only platform administrators can create organizations.")

        clean_name = name.strip()
        clean_slug = slug.strip().lower()

        if self.db.scalars(select(Organization).where(Organization.slug == clean_slug)).first():
            raise ConflictError(f"Organization slug '{clean_slug}' is already taken")
        self._ensure_name_available(clean_name)

        org = Organization(
            name=clean_name,
            slug=clean_slug,
            max_concurrent_scans=max_concurrent_scans,
            is_active=True,
        )
        self.db.add(org)
        self.db.flush()

        membership = OrganizationMembership(
            organization_id=org.id,
            user_id=actor.id,
            role=UserRole.ADMIN,
        )
        self.db.add(membership)
        audit_log(
            self.db,
            action=AuditAction.ORG_CREATED,
            resource_type="organization",
            resource_id=str(org.id),
            organization_id=org.id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={"name": clean_name, "slug": clean_slug},
            commit=False,
        )
        self.db.commit()
        return org

    def get_organization(self, org_id: uuid.UUID) -> Organization:
        org = self.db.get(Organization, org_id)
        if not org:
            raise NotFoundError(f"Organization {org_id} not found")
        return org

    def list_user_organizations(self, user: User) -> list[Organization]:
        if user.is_superuser:
            return list(self.db.scalars(select(Organization)).all())
        stmt = (
            select(Organization)
            .join(OrganizationMembership, OrganizationMembership.organization_id == Organization.id)
            .where(OrganizationMembership.user_id == user.id)
        )
        return list(self.db.scalars(stmt).all())

    def update_organization(
        self,
        org_id: uuid.UUID,
        name: str | None = None,
        max_concurrent_scans: int | None = None,
        is_active: bool | None = None,
        actor: User | None = None,
    ) -> Organization:
        org = self.get_organization(org_id)
        activation_change = is_active is not None and is_active != org.is_active
        if activation_change and not (actor and actor.is_superuser):
            # Deactivation hides the organization from its own admins, so only a
            # superuser can undo it.
            raise PermissionDeniedError(
                "Only a platform administrator can activate or deactivate an organization"
            )
        changes: dict[str, Any] = {}
        clean_name = name.strip() if name else ""
        if clean_name and clean_name != org.name:
            self._ensure_name_available(clean_name, exclude_id=org.id)
            changes["name"] = clean_name
        if max_concurrent_scans is not None and max_concurrent_scans != org.max_concurrent_scans:
            changes["max_concurrent_scans"] = max_concurrent_scans
        if activation_change:
            changes["is_active"] = is_active
        if not changes:
            return org

        for field, value in changes.items():
            setattr(org, field, value)
        audit_log(
            self.db,
            action=AuditAction.ORG_UPDATED,
            resource_type="organization",
            resource_id=str(org.id),
            organization_id=org.id,
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else None,
            metadata=changes,
            commit=False,
        )
        self.db.commit()
        return org

    def _ensure_admin_remains(self, org_id: uuid.UUID, mem: OrganizationMembership) -> None:
        """Refuse a change that would leave the organization without an admin."""
        if mem.role != UserRole.ADMIN:
            return
        admin_count = self.db.scalar(
            select(func.count()).select_from(OrganizationMembership).where(
                OrganizationMembership.organization_id == org_id,
                OrganizationMembership.role == UserRole.ADMIN,
            )
        )
        if admin_count <= 1:
            raise ConflictError("The organization must keep at least one admin")

    def list_members(self, org_id: uuid.UUID) -> list[dict[str, Any]]:
        self.get_organization(org_id)
        stmt = (
            select(OrganizationMembership, User)
            .join(User, OrganizationMembership.user_id == User.id)
            .where(OrganizationMembership.organization_id == org_id)
        )
        results = self.db.execute(stmt).all()
        members = []
        for mem, user in results:
            members.append({
                "id": mem.id,
                "user_id": user.id,
                "organization_id": org_id,
                "email": user.email,
                "full_name": user.full_name,
                "role": mem.role,
                "joined_at": mem.joined_at,
            })
        return members

    def add_member(
        self,
        org_id: uuid.UUID,
        email: str,
        role: UserRole,
        actor: User,
    ) -> dict[str, Any]:
        self.get_organization(org_id)
        clean_email = email.strip().lower()
        user = self.db.scalars(select(User).where(User.email == clean_email)).first()
        if not user:
            raise NotFoundError(f"User with email '{clean_email}' not found")

        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == user.id,
        )
        if self.db.scalars(stmt).first():
            raise ConflictError(f"User '{clean_email}' is already a member of this organization")

        mem = OrganizationMembership(
            organization_id=org_id,
            user_id=user.id,
            role=role,
            invited_by=actor.id,
        )
        self.db.add(mem)
        # Flushing assigns the id and join time used by the audit entry and the response.
        self.db.flush()
        member = {
            "id": mem.id,
            "user_id": user.id,
            "organization_id": org_id,
            "email": user.email,
            "full_name": user.full_name,
            "role": mem.role,
            "joined_at": mem.joined_at,
        }

        audit_log(
            self.db,
            action=AuditAction.ORG_MEMBER_ADDED,
            resource_type="membership",
            resource_id=str(mem.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={"member_user_id": str(user.id), "role": role.value},
            commit=False,
        )
        self.db.commit()
        return member

    def update_member_role(
        self,
        org_id: uuid.UUID,
        target_user_id: uuid.UUID,
        new_role: UserRole,
        actor: User,
    ) -> None:
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == target_user_id,
        )
        mem = self.db.scalars(stmt).first()
        if not mem:
            raise NotFoundError("Membership record not found")
        if new_role != UserRole.ADMIN:
            self._ensure_admin_remains(org_id, mem)

        previous_role = mem.role
        mem.role = new_role
        audit_log(
            self.db,
            action=AuditAction.USER_ASSIGN_ROLE,
            resource_type="membership",
            resource_id=str(mem.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={
                "assigned_user_id": str(target_user_id),
                "previous_role": previous_role.value,
                "new_role": new_role.value,
            },
            commit=False,
        )
        self.db.commit()

    def remove_member(
        self,
        org_id: uuid.UUID,
        target_user_id: uuid.UUID,
        actor: User,
    ) -> None:
        stmt = select(OrganizationMembership).where(
            OrganizationMembership.organization_id == org_id,
            OrganizationMembership.user_id == target_user_id,
        )
        mem = self.db.scalars(stmt).first()
        if not mem:
            raise NotFoundError("Membership record not found")
        self._ensure_admin_remains(org_id, mem)

        removed_role = mem.role
        self.db.delete(mem)
        audit_log(
            self.db,
            action=AuditAction.ORG_MEMBER_REMOVED,
            resource_type="membership",
            resource_id=str(target_user_id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={"removed_user_id": str(target_user_id), "role": removed_role.value},
            commit=False,
        )
        self.db.commit()
