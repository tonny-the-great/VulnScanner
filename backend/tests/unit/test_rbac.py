"""Unit tests for Role-Based Access Control hierarchy."""

import uuid

import pytest

from app.core.exceptions import PermissionDeniedError
from app.core.rbac import OrgAuthContext, has_minimum_role
from app.models.membership import UserRole
from app.models.user import User


def test_role_hierarchy_ordering():
    assert has_minimum_role(UserRole.ADMIN, UserRole.ADMIN) is True
    assert has_minimum_role(UserRole.ADMIN, UserRole.ANALYST) is True
    assert has_minimum_role(UserRole.ADMIN, UserRole.VIEWER) is True

    assert has_minimum_role(UserRole.ANALYST, UserRole.ADMIN) is False
    assert has_minimum_role(UserRole.ANALYST, UserRole.ANALYST) is True
    assert has_minimum_role(UserRole.ANALYST, UserRole.VIEWER) is True

    assert has_minimum_role(UserRole.VIEWER, UserRole.ADMIN) is False
    assert has_minimum_role(UserRole.VIEWER, UserRole.ANALYST) is False
    assert has_minimum_role(UserRole.VIEWER, UserRole.VIEWER) is True


def test_auth_context_check_permission():
    user = User(
        email="analyst@corp.local",
        password_hash="hash",
        full_name="Test Analyst",
        is_active=True,
    )
    ctx = OrgAuthContext(
        organization_id=uuid.uuid4(),
        user=user,
        role=UserRole.ANALYST,
    )
    # Analyst can view and analyze, but cannot perform Admin tasks
    ctx.check_permission(UserRole.VIEWER)
    ctx.check_permission(UserRole.ANALYST)

    with pytest.raises(PermissionDeniedError, match="Requires 'admin' role"):
        ctx.check_permission(UserRole.ADMIN)


def test_superuser_bypasses_role_checks():
    super_user = User(
        email="super@corp.local",
        password_hash="hash",
        full_name="Super Admin",
        is_active=True,
        is_superuser=True,
    )
    ctx = OrgAuthContext(
        organization_id=uuid.uuid4(),
        user=super_user,
        role=UserRole.VIEWER,
    )
    # Even if membership role is viewer, is_superuser allows all roles
    ctx.check_permission(UserRole.ADMIN)
