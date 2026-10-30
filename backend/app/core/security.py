"""
Security utilities: password hashing (Argon2id), JWT creation/verification,
token revocation, cookie helpers and the current-user dependencies.

Sessions are bound to the user's password hash: every token carries a 'pwv'
(password version) claim derived from it, so changing the password ends every
session that was issued before the change.

NEVER expose password_hash in API responses.
NEVER log tokens, hashes, or credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import jwt
from argon2 import PasswordHasher
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.exceptions import RateLimitExceededError
from app.core.redis_client import get_redis_safe, mark_redis_failed
from app.database import get_db

if TYPE_CHECKING:
    from app.models.user import User

settings = get_settings()

# ── Password hashing ──────────────────────────────────────────────────────────
# Argon2id with OWASP-recommended parameters
_ph = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

# Each hash or verification allocates memory_cost (64 MiB). Bounding concurrent
# operations keeps a burst of logins from exhausting the API process's memory.
_hash_slots = threading.BoundedSemaphore(settings.PASSWORD_HASH_CONCURRENCY)
# Waiting threads occupy the shared sync-endpoint thread pool, so the wait is
# bounded: under a burst the request is refused (429) instead of starving every
# other endpoint of threads.
_HASH_SLOT_WAIT_SECONDS = 5.0
_HASH_BUSY_RETRY_AFTER = 5


def _acquire_hash_slot() -> None:
    if not _hash_slots.acquire(timeout=_HASH_SLOT_WAIT_SECONDS):
        raise RateLimitExceededError(_HASH_BUSY_RETRY_AFTER)


def hash_password(plain: str) -> str:
    """Hash a plaintext password with Argon2id. Returns the full encoded hash.

    Raises RateLimitExceededError when no hashing slot frees up in time.
    """
    _acquire_hash_slot()
    try:
        return _ph.hash(plain)
    finally:
        _hash_slots.release()


def verify_password(stored_hash: str, plain: str) -> bool:
    """
    Verify a plaintext password against a stored Argon2id hash.

    Returns False for any verification failure. The only exception raised is
    RateLimitExceededError when the server is too busy to verify at all, so an
    overload is never counted as a wrong password.
    """
    _acquire_hash_slot()
    try:
        return _ph.verify(stored_hash, plain)
    except Exception:
        return False
    finally:
        _hash_slots.release()


def needs_rehash(stored_hash: str) -> bool:
    """True if the hash was created with outdated parameters."""
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False


def password_version(password_hash: str) -> str:
    """Short keyed fingerprint of a password hash, stored in tokens as 'pwv'.

    It changes whenever the hash changes, and cannot be computed without
    SESSION_SECRET, so it reveals nothing about the hash itself.
    """
    return hmac.new(
        settings.SESSION_SECRET.encode(), password_hash.encode(), hashlib.sha256
    ).hexdigest()[:16]


def token_matches_password(payload: dict[str, Any], password_hash: str) -> bool:
    """True if the token's 'pwv' claim belongs to the user's current password hash."""
    claim = payload.get("pwv")
    if not isinstance(claim, str) or not claim:
        return False
    return hmac.compare_digest(claim, password_version(password_hash))


# ── JWT ───────────────────────────────────────────────────────────────────────
_ALGORITHM = "HS256"
_ACCESS_TOKEN_TYPE = "access"
_REFRESH_TOKEN_TYPE = "refresh"

SESSION_INVALID_DETAIL = "Session is no longer valid. Please log in again."


def _create_token(
    subject: str,
    token_type: str,
    expires_delta: timedelta,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": subject,
        "type": token_type,
        "iat": now,
        "exp": now + expires_delta,
        "jti": secrets.token_hex(16),  # unique token ID (revocation, single-use refresh)
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.SESSION_SECRET, algorithm=_ALGORITHM)


def _password_claims(password_hash: str | None) -> dict[str, Any] | None:
    return {"pwv": password_version(password_hash)} if password_hash else None


def create_access_token(user_id: str | uuid.UUID, password_hash: str | None = None) -> str:
    """Issue an access token; pass the user's password hash to bind it to the password."""
    return _create_token(
        subject=str(user_id),
        token_type=_ACCESS_TOKEN_TYPE,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        extra_claims=_password_claims(password_hash),
    )


def create_refresh_token(user_id: str | uuid.UUID, password_hash: str | None = None) -> str:
    """Issue a refresh token; pass the user's password hash to bind it to the password."""
    return _create_token(
        subject=str(user_id),
        token_type=_REFRESH_TOKEN_TYPE,
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        extra_claims=_password_claims(password_hash),
    )


# ── Token revocation / Blocklist ──────────────────────────────────────────────
# Revoked (and consumed) token ids live in Redis when it is reachable. Otherwise
# each API process keeps them in memory until the token would have expired.
_REVOCATION_KEY_PREFIX = "revoked_token:"
_REVOKED_TOKENS_FALLBACK: dict[str, float] = {}
_revocation_lock = threading.Lock()


def _cleanup_fallback_revocations(now_ts: float) -> None:
    """Drop expired entries; the caller holds _revocation_lock."""
    expired = [k for k, v in _REVOKED_TOKENS_FALLBACK.items() if v <= now_ts]
    for k in expired:
        _REVOKED_TOKENS_FALLBACK.pop(k, None)


def _revoked_locally(jti: str, now_ts: float) -> bool:
    """True while the in-process blocklist holds jti; the caller holds _revocation_lock."""
    expires_at = _REVOKED_TOKENS_FALLBACK.get(jti)
    if expires_at is None:
        return False
    if expires_at > now_ts:
        return True
    del _REVOKED_TOKENS_FALLBACK[jti]
    return False


def revoke_token(token: str) -> None:
    """Revoke a token by adding its jti to the blocklist until expiration."""
    try:
        payload = jwt.decode(
            token, settings.SESSION_SECRET, algorithms=[_ALGORITHM], options={"verify_exp": False}
        )
    except Exception:
        return

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti:
        return

    now_ts = time.time()
    ttl = int(exp - now_ts) if exp else settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    if ttl <= 0:
        return

    redis_conn = get_redis_safe()
    if redis_conn:
        try:
            redis_conn.setex(f"{_REVOCATION_KEY_PREFIX}{jti}", ttl, "1")
            return
        except Exception:
            mark_redis_failed()

    with _revocation_lock:
        _cleanup_fallback_revocations(now_ts)
        _REVOKED_TOKENS_FALLBACK[jti] = now_ts + ttl


def is_token_revoked(jti: str) -> bool:
    """Check if a token JTI has been revoked (or, for refresh tokens, already used)."""
    with _revocation_lock:
        if _revoked_locally(jti, time.time()):
            return True

    redis_conn = get_redis_safe()
    if redis_conn:
        try:
            return bool(redis_conn.exists(f"{_REVOCATION_KEY_PREFIX}{jti}"))
        except Exception:
            mark_redis_failed()

    return False


def consume_token_once(jti: str, ttl_seconds: int) -> bool:
    """Atomically mark a token id as used; True only for the first caller.

    The id is recorded under the revocation key, so a consumed token also counts
    as revoked, and a revoked token cannot be consumed. Without Redis the check
    is atomic within this API process only.
    """
    ttl = max(1, int(ttl_seconds))
    now_ts = time.time()
    with _revocation_lock:
        # Ids consumed or revoked while Redis was unreachable stay used here.
        if _revoked_locally(jti, now_ts):
            return False

    redis_conn = get_redis_safe()
    if redis_conn:
        try:
            return bool(redis_conn.set(f"{_REVOCATION_KEY_PREFIX}{jti}", "1", nx=True, ex=ttl))
        except Exception:
            mark_redis_failed()

    with _revocation_lock:
        if _revoked_locally(jti, now_ts):
            return False
        _cleanup_fallback_revocations(now_ts)
        _REVOKED_TOKENS_FALLBACK[jti] = now_ts + ttl
        return True


def decode_token(token: str, expected_type: str, check_revoked: bool = True) -> dict[str, Any]:
    """
    Decode and validate a JWT.

    Raises HTTPException 401 for any invalid/expired/wrong-type token, and for a
    revoked one unless check_revoked is False (the refresh endpoint consumes the
    token id atomically instead).
    """
    try:
        payload = jwt.decode(token, settings.SESSION_SECRET, algorithms=[_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    if payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
        )

    jti = payload.get("jti")
    if check_revoked and jti and is_token_revoked(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def token_subject(payload: dict[str, Any]) -> uuid.UUID | None:
    """The token's 'sub' claim as a UUID, or None when it is missing or malformed."""
    try:
        return uuid.UUID(payload.get("sub"))
    except (ValueError, TypeError, AttributeError):
        return None


# ── Cookie helpers ────────────────────────────────────────────────────────────
_ACCESS_COOKIE_NAME = "access_token"
_REFRESH_COOKIE_NAME = "refresh_token"
# The refresh token is only ever needed by the auth endpoints (refresh, logout),
# so browsers do not attach it to any other request.
REFRESH_COOKIE_PATH = "/api/v1/auth"
_LEGACY_REFRESH_COOKIE_PATH = "/"
# In production (HTTPS) cookies are Secure. Dev uses HTTP so we can't force it.
_SECURE_COOKIES = not settings.is_development and not settings.is_testing
_ACCESS_COOKIE_KWARGS: dict[str, Any] = {
    "path": "/",
    "httponly": True,
    "samesite": "lax",
    "secure": _SECURE_COOKIES,
}
_REFRESH_COOKIE_KWARGS: dict[str, Any] = {
    "path": REFRESH_COOKIE_PATH,
    "httponly": True,
    "samesite": "strict",
    "secure": _SECURE_COOKIES,
}
_LEGACY_REFRESH_COOKIE_KWARGS: dict[str, Any] = {
    "path": _LEGACY_REFRESH_COOKIE_PATH,
    "httponly": True,
    "samesite": "lax",
    "secure": _SECURE_COOKIES,
}


def set_auth_cookies(response: Any, access: str, refresh: str) -> None:
    """
    Write the issued access and refresh tokens as httpOnly cookies.
    """
    # Earlier versions set the refresh cookie at '/'; drop that copy so the
    # browser does not keep sending a stale duplicate to the auth endpoints.
    response.delete_cookie(_REFRESH_COOKIE_NAME, **_LEGACY_REFRESH_COOKIE_KWARGS)
    response.set_cookie(
        key=_ACCESS_COOKIE_NAME,
        value=access,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **_ACCESS_COOKIE_KWARGS,
    )
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=refresh,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        **_REFRESH_COOKIE_KWARGS,
    )


def clear_auth_cookies(response: Any) -> None:
    """Clear both auth cookies (including a legacy refresh cookie at '/') on logout."""
    response.delete_cookie(_ACCESS_COOKIE_NAME, **_ACCESS_COOKIE_KWARGS)
    response.delete_cookie(_REFRESH_COOKIE_NAME, **_REFRESH_COOKIE_KWARGS)
    response.delete_cookie(_REFRESH_COOKIE_NAME, **_LEGACY_REFRESH_COOKIE_KWARGS)


def access_token_from_request(request: Request) -> str | None:
    """The access token from the cookie, or else from an 'Authorization: Bearer' header."""
    token = request.cookies.get(_ACCESS_COOKIE_NAME)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    return token or None


# ── Current user dependency ───────────────────────────────────────────────────
def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:  # noqa: F821 — forward ref
    """
    FastAPI dependency: extract and validate the access token cookie,
    then return the active User from the database.

    Raises 401 if the token is missing, invalid or issued before the last
    password change, or the user is inactive. Account lockout only guards
    password authentication, so it does not end existing sessions.
    """
    from app.models.user import User

    token = access_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Please log in.",
        )

    payload = decode_token(token, expected_type=_ACCESS_TOKEN_TYPE)
    subject = token_subject(payload)
    if subject is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token.")
    user = db.get(User, subject)
    if user and not user.is_active:
        user = None
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or account deactivated.",
        )
    if not token_matches_password(payload, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=SESSION_INVALID_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User | None:
    """Like get_current_user, but returns None instead of raising when not signed in."""
    try:
        return get_current_user(request, db)
    except HTTPException:
        return None


def get_current_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """Dependency: require platform-level superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required.",
        )
    return current_user
