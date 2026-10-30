"""Authentication endpoints."""

from __future__ import annotations

import contextlib
import logging
import time

from fastapi import APIRouter, Cookie, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.audit import AuditAction, audit_log
from app.core.exceptions import AuthenticationError, PermissionDeniedError
from app.core.rate_limit import enforce_rate_limit, rate_limit_by_ip, rate_limit_by_user
from app.core.security import (
    SESSION_INVALID_DETAIL,
    access_token_from_request,
    clear_auth_cookies,
    consume_token_once,
    decode_token,
    get_current_user,
    get_optional_current_user,
    revoke_token,
    set_auth_cookies,
    token_matches_password,
    token_subject,
)
from app.database import get_db
from app.models.membership import OrganizationMembership
from app.models.organization import Organization
from app.models.user import User
from app.schemas.auth import (
    ChangePasswordRequest,
    CurrentUserResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from app.services.auth_service import AuthService, issue_session_tokens

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

_REFRESH_REUSED_DETAIL = "Refresh token has already been used. Please log in again."


def _token_response(access_token: str) -> TokenResponse:
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",  # noqa: S106 - the OAuth token type, not a secret
        expires_in=get_settings().ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_by_ip("login-ip", "LOGIN_RATE_LIMIT"))],
)
def login(
    req: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> TokenResponse:
    # Per-account limit as well, so attempts spread over many addresses still slow down.
    enforce_rate_limit("login-email", req.email, get_settings().LOGIN_RATE_LIMIT)
    svc = AuthService(db)
    _user, access_token, refresh_token = svc.authenticate_user(req.email, req.password)
    set_auth_cookies(response, access_token, refresh_token)
    return _token_response(access_token)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_by_ip("register", "REGISTER_RATE_LIMIT"))],
)
def register(
    req: RegisterRequest,
    current_user: User | None = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
) -> UserResponse:
    creator = current_user if current_user is not None and current_user.is_superuser else None
    if not get_settings().ALLOW_SELF_REGISTRATION and creator is None:
        raise PermissionDeniedError(
            "Self-registration is disabled. Ask a platform administrator to create your account."
        )
    svc = AuthService(db)
    user = svc.register_user(req.email, req.password, req.full_name, created_by=creator)
    return UserResponse.model_validate(user)


def _audit_logout(db: Session, token: str) -> None:
    """Best effort: record the logout when the access token names a user. Never raises."""
    try:
        subject = token_subject(decode_token(token, expected_type="access"))
    except Exception:
        return  # invalid, expired or already revoked: nothing to attribute
    if subject is None:
        return
    try:
        audit_log(db, action=AuditAction.AUTH_LOGOUT, resource_type="auth", actor_id=subject)
    except Exception:
        # For example the user was deleted meanwhile; logout proceeds regardless.
        logger.warning("Could not audit logout for user %s", subject, exc_info=True)
        with contextlib.suppress(Exception):
            db.rollback()


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> None:
    access_token = access_token_from_request(request)
    if access_token:
        _audit_logout(db, access_token)
        revoke_token(access_token)
    if refresh_token:
        revoke_token(refresh_token)
    clear_auth_cookies(response)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_by_ip("refresh", "REFRESH_RATE_LIMIT"))],
)
def refresh_token(
    response: Response,
    refresh_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> TokenResponse:
    if not refresh_token:
        raise AuthenticationError("Refresh token missing")

    # Signature, expiry and type are checked here; whether the token was already
    # used (or revoked) is decided atomically by consume_token_once below.
    payload = decode_token(refresh_token, expected_type="refresh", check_revoked=False)
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise AuthenticationError("Invalid user session")
    subject = token_subject(payload)

    # Rotate: a refresh token is single-use, so a stolen copy cannot be replayed.
    ttl = int(payload.get("exp", 0) - time.time())
    if not consume_token_once(jti, ttl):
        owner = db.get(User, subject) if subject else None
        audit_log(
            db,
            action=AuditAction.AUTH_REFRESH_REUSE,
            resource_type="auth",
            actor_id=owner.id if owner else None,
            actor_email=owner.email if owner else None,
            metadata={"reason": "refresh_token_reuse"},
            commit=True,
        )
        raise AuthenticationError(_REFRESH_REUSED_DETAIL)

    user = db.get(User, subject) if subject else None
    if not user or not user.is_active:
        raise AuthenticationError("Invalid user session")
    if not token_matches_password(payload, user.password_hash):
        raise AuthenticationError(SESSION_INVALID_DETAIL)

    new_access, new_refresh = issue_session_tokens(user.id, user.password_hash)
    set_auth_cookies(response, new_access, new_refresh)
    return _token_response(new_access)


@router.get("/me", response_model=CurrentUserResponse)
def get_current_user_profile(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CurrentUserResponse:
    # One joined query instead of a lazy load per membership and organization.
    rows = db.execute(
        select(
            OrganizationMembership.organization_id,
            Organization.name,
            OrganizationMembership.role,
        )
        .join(Organization, Organization.id == OrganizationMembership.organization_id)
        .where(OrganizationMembership.user_id == user.id)
        .order_by(OrganizationMembership.joined_at, OrganizationMembership.id)
    ).all()
    memberships_data = [
        {
            "organization_id": str(organization_id),
            "organization_name": organization_name or "",
            "role": role.value,
        }
        for organization_id, organization_name, role in rows
    ]
    return CurrentUserResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        created_at=user.created_at,
        memberships=memberships_data,
    )


@router.post(
    "/change-password",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limit_by_user("password-change", "PASSWORD_CHANGE_RATE_LIMIT"))],
)
def change_password(
    req: ChangePasswordRequest,
    response: Response,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    # Sessions are bound to the password, so every other session ends here;
    # the caller gets fresh cookies and stays signed in.
    svc = AuthService(db)
    access_token, refresh_token = svc.change_password(user, req.current_password, req.new_password)
    set_auth_cookies(response, access_token, refresh_token)
