"""Authentication and user account service."""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import ColumnElement, and_, case, or_, select, update
from sqlalchemy.orm import Session

from app.core.audit import AuditAction, audit_log
from app.core.exceptions import AuthenticationError, ConflictError, ValidationError
from app.core.password_policy import validate_password_policy
from app.core.security import (
    create_access_token,
    create_refresh_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.models.user import User

_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(16))

# Unknown, inactive and locked accounts all get this message, so a response never
# reveals whether an address has an account or whether it is locked.
_INVALID_CREDENTIALS = "Invalid email or password"
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

logger = logging.getLogger(__name__)


def _not_locked_at(now: datetime) -> ColumnElement[bool]:
    """SQL condition: the account has no lock, or its lock has expired by 'now'."""
    return or_(User.locked_until.is_(None), User.locked_until <= now)


def issue_session_tokens(user_id: uuid.UUID, password_hash: str) -> tuple[str, str]:
    """Return (access_token, refresh_token) bound to the user's current password."""
    return (
        create_access_token(user_id, password_hash),
        create_refresh_token(user_id, password_hash),
    )


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def authenticate_user(
        self,
        email: str,
        password: str,
        ip_address: str | None = None,
    ) -> tuple[User, str, str]:
        """Verify user credentials, enforce lockout, and return (user, access_token, refresh_token).

        ip_address overrides the address recorded in audit entries; by default it
        comes from the trusted-proxy-aware request context.
        """
        clean_email = email.strip().lower()
        stmt = select(User).where(User.email == clean_email)
        user = self.db.scalars(stmt).first()

        if not user or not user.is_active:
            # Spend the same hashing time as a real check so response timing
            # does not reveal which email addresses have accounts.
            verify_password(_DUMMY_PASSWORD_HASH, password)
            self._audit_login_failure(
                actor_email=clean_email,
                ip_address=ip_address,
                metadata={"reason": "invalid_credentials_or_inactive"},
            )
            raise AuthenticationError(_INVALID_CREDENTIALS)

        if user.is_locked:
            # Verify anyway so a locked account answers as slowly as any other.
            # The attempt is not counted: the lock already runs its course.
            verify_password(user.password_hash, password)
            self._audit_login_failure(
                actor_id=user.id,
                actor_email=user.email,
                ip_address=ip_address,
                metadata={"reason": "account_locked"},
            )
            raise AuthenticationError(_INVALID_CREDENTIALS)

        if not verify_password(user.password_hash, password):
            self._record_failed_password(user, ip_address)
            raise AuthenticationError(_INVALID_CREDENTIALS)

        user_id, user_email = user.id, user.email
        password_hash = user.password_hash
        values: dict[str, object] = {}
        if needs_rehash(password_hash):
            # Upgrading the hash also changes the session binding ('pwv'), so the
            # user's other sessions end once, when the hashing parameters change.
            password_hash = hash_password(password)
            values["password_hash"] = password_hash

        now = datetime.now(UTC)
        result = self.db.execute(
            update(User)
            # A concurrent request may have locked the account while the password
            # was being verified; such a lock is not undone by this login.
            .where(User.id == user_id, _not_locked_at(now))
            .values(failed_login_attempts=0, locked_until=None, last_login_at=now, **values)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            self.db.rollback()
            self._audit_login_failure(
                actor_id=user_id,
                actor_email=user_email,
                ip_address=ip_address,
                metadata={"reason": "account_locked"},
            )
            raise AuthenticationError(_INVALID_CREDENTIALS)

        audit_log(
            self.db,
            action=AuditAction.AUTH_LOGIN,
            resource_type="auth",
            actor_id=user_id,
            actor_email=user_email,
            ip_address=ip_address,
            commit=False,
        )
        self.db.commit()

        access_token, refresh_token = issue_session_tokens(user_id, password_hash)
        return user, access_token, refresh_token

    def _audit_login_failure(
        self,
        *,
        actor_email: str,
        metadata: dict[str, object],
        actor_id: uuid.UUID | None = None,
        ip_address: str | None = None,
    ) -> None:
        # Committed on its own: the request ends in an error, but the entry must persist.
        audit_log(
            self.db,
            action=AuditAction.AUTH_LOGIN_FAILED,
            resource_type="auth",
            actor_id=actor_id,
            actor_email=actor_email,
            ip_address=ip_address,
            metadata=metadata,
            commit=True,
        )

    def _record_failed_password(self, user: User, ip_address: str | None) -> None:
        """Count a wrong password atomically and lock the account at the threshold.

        Concurrent failures cannot lose increments, and only one of them applies
        (and audits) the lock. A lock that has already expired starts a new count.
        """
        user_id, user_email = user.id, user.email
        now = datetime.now(UTC)
        lock_expired = and_(User.locked_until.is_not(None), User.locked_until <= now)
        attempts = self.db.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=case(
                    (lock_expired, 1), else_=User.failed_login_attempts + 1
                ),
                locked_until=case((lock_expired, None), else_=User.locked_until),
            )
            .returning(User.failed_login_attempts)
            .execution_options(synchronize_session=False)
        ).scalar_one()

        if attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
            locked = self.db.execute(
                update(User)
                .where(User.id == user_id, _not_locked_at(now))
                .values(locked_until=now + LOCKOUT_DURATION)
                .execution_options(synchronize_session=False)
            )
            if locked.rowcount == 1:
                audit_log(
                    self.db,
                    action=AuditAction.AUTH_ACCOUNT_LOCKED,
                    resource_type="user",
                    resource_id=str(user_id),
                    actor_id=user_id,
                    actor_email=user_email,
                    ip_address=ip_address,
                    metadata={
                        "failed_attempts": attempts,
                        "lockout_minutes": int(LOCKOUT_DURATION.total_seconds() // 60),
                    },
                    commit=False,
                )

        audit_log(
            self.db,
            action=AuditAction.AUTH_LOGIN_FAILED,
            resource_type="auth",
            actor_id=user_id,
            actor_email=user_email,
            ip_address=ip_address,
            metadata={"reason": "invalid_password", "failed_attempts": attempts},
            commit=False,
        )
        self.db.commit()

    def register_user(
        self,
        email: str,
        password: str,
        full_name: str,
        is_superuser: bool = False,
        created_by: User | None = None,
    ) -> User:
        """Register a new user account.

        created_by is the superuser creating the account, if any; it becomes the
        actor of the audit entry (otherwise the new user is).
        """
        clean_email = email.strip().lower()
        stmt = select(User).where(User.email == clean_email)
        if self.db.scalars(stmt).first():
            raise ConflictError(f"User with email '{clean_email}' already exists")

        pw_hash = hash_password(password)
        user = User(
            email=clean_email,
            password_hash=pw_hash,
            full_name=full_name.strip(),
            is_active=True,
            is_superuser=is_superuser,
        )
        self.db.add(user)
        # The audit entry references the new user, so its row must exist first.
        self.db.flush()
        audit_log(
            self.db,
            action=AuditAction.AUTH_REGISTER,
            resource_type="user",
            resource_id=str(user.id),
            actor_id=created_by.id if created_by else user.id,
            actor_email=created_by.email if created_by else clean_email,
            metadata={
                "email": clean_email,
                "created_by_superuser": created_by is not None,
                "is_superuser": is_superuser,
            },
            commit=False,
        )
        self.db.commit()
        return user

    def change_password(
        self,
        user: User,
        current_password: str,
        new_password: str,
    ) -> tuple[str, str]:
        """Change the password after verifying the current one.

        Every session issued before the change stops working. Returns a fresh
        (access_token, refresh_token) pair for the caller's own session.
        """
        if not verify_password(user.password_hash, current_password):
            raise AuthenticationError("Current password is incorrect")
        if new_password == current_password:
            raise ValidationError("New password must differ from the current password")
        try:
            validate_password_policy(new_password, user.email)
        except ValueError as exc:
            raise ValidationError(str(exc)) from None

        user_id = user.id
        new_hash = hash_password(new_password)
        user.password_hash = new_hash
        audit_log(
            self.db,
            action=AuditAction.AUTH_PASSWORD_CHANGE,
            resource_type="user",
            resource_id=str(user_id),
            actor_id=user_id,
            actor_email=user.email,
            commit=False,
        )
        self.db.commit()
        return issue_session_tokens(user_id, new_hash)
