"""
Role-Based Access Control dependencies.

Authorization is ALWAYS enforced in the service/router layer — never
rely on hiding UI elements.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from app.core.exceptions import PermissionDeniedError
from app.core.security import get_current_user
from app.database import get_db
from app.models.membership import UserRole

if TYPE_CHECKING:
    from app.models.membership import OrganizationMembership
    from app.models.organization import Organization
    from app.models.user import User

ROLE_HIERARCHY: dict[UserRole, int] = {
    UserRole.VIEWER: 1,
    UserRole.ANALYST: 2,
    UserRole.ADMIN: 3,
}


def has_minimum_role(user_role: UserRole, required_role: UserRole) -> bool:
    """Return True if user_role satisfies required_role in the hierarchy."""
    return ROLE_HIERARCHY.get(user_role, 0) >= ROLE_HIERARCHY.get(required_role, 0)


@dataclass
class OrgAuthContext:
    """
    Passed to route handlers when org-level authorization succeeds.
    Contains the resolved user, their role, and the organization.
    """

    user: User
    membership: OrganizationMembership | None = None
    organization: Organization | None = None
    effective_role: UserRole | None = None
    organization_id: uuid.UUID | None = None
    role: UserRole | None = None

    def __post_init__(self) -> None:
        if self.role and not self.effective_role:
            self.effective_role = self.role
        elif self.effective_role and not self.role:
            self.role = self.effective_role

    @property
    def is_superuser(self) -> bool:
        return self.user.is_superuser

    def check_permission(self, minimum_role: UserRole) -> None:
        if self.is_superuser:
            return
        if not self.effective_role or not has_minimum_role(self.effective_role, minimum_role):
            raise PermissionDeniedError(f"Requires '{minimum_role.value}' role")


def require_role(minimum_role: UserRole):
    """
    Dependency factory: verify the current user has at least minimum_role
    for the organization specified by the `organization_id` path parameter.
    """
    allowed_roles = [r for r in UserRole if has_minimum_role(r, minimum_role)]
    return require_org_role(*allowed_roles)


def require_org_role(*required_roles: UserRole):
    """
    Dependency factory: verify the current user is a member of the org
    specified by the `organization_id` path parameter with at least one
    of the given roles.
    """

    def _dependency(
        organization_id: uuid.UUID = Path(...),
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> OrgAuthContext:
        from app.models.membership import OrganizationMembership
        from app.models.organization import Organization

        org = db.get(Organization, organization_id)
        if not org or not org.is_active:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Organization not found.",
            )

        if current_user.is_superuser:
            return OrgAuthContext(
                user=current_user,
                membership=None,
                organization=org,
                effective_role=UserRole.ADMIN,
                organization_id=organization_id,
            )

        membership = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == current_user.id,
            )
            .first()
        )

        if not membership:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not a member of this organization.",
            )

        if required_roles and membership.role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This action requires one of the following roles: "
                    f"{', '.join(r.value for r in required_roles)}. "
                    f"Your role is: {membership.role.value}."
                ),
            )

        return OrgAuthContext(
            user=current_user,
            membership=membership,
            organization=org,
            effective_role=membership.role,
            organization_id=organization_id,
        )

    return _dependency


def require_any_org_member():
    """Shorthand: allow any organization member (admin, analyst, viewer)."""
    return require_org_role(*list(UserRole))
