"""Lockout, session binding, single-use refresh, cookies, rate limits and tenancy controls."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app.config import get_settings
from app.core import rate_limit
from app.core.rate_limit import reset_rate_limits
from app.core.security import hash_password, needs_rehash, verify_password
from app.database import SessionLocal
from app.main import app
from app.models.audit import AuditLog
from app.models.user import User
from app.services import auth_service

PASSWORD = "HardeningPassword-2026!"
NEW_PASSWORD = "Rotated-Hardening-Secret-2026!"
GENERIC_LOGIN_ERROR = "Invalid email or password"
SESSION_INVALID = "Session is no longer valid. Please log in again."


def new_email(prefix: str = "hardening") -> str:
    return f"{prefix}-{uuid.uuid4().hex}@example.com"


def register(client: TestClient, email: str | None = None, password: str = PASSWORD) -> str:
    email = email or new_email()
    response = client.post("/api/v1/auth/register", json={
        "email": email, "password": password, "full_name": "Hardening Tester",
    })
    assert response.status_code == 201, response.text
    return email


def login(client: TestClient, email: str, password: str = PASSWORD, **kwargs):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password}, **kwargs)


def signed_in_client() -> tuple[TestClient, str]:
    client = TestClient(app)
    email = register(client)
    assert login(client, email).status_code == 200
    return client, email


def load_user(db, email: str) -> User:
    db.expire_all()
    return db.scalars(select(User).where(User.email == email)).one()


def create_superuser(db) -> tuple[TestClient, User]:
    user = User(
        email=new_email("superuser"), display_name="Platform Admin",
        password_hash=hash_password(PASSWORD), is_superuser=True,
    )
    db.add(user)
    db.commit()
    client = TestClient(app)
    assert login(client, user.email).status_code == 200
    return client, user


def audit_entries(db, action: str, **filters) -> list[AuditLog]:
    db.expire_all()
    stmt = select(AuditLog).where(AuditLog.action == action)
    for column, value in filters.items():
        stmt = stmt.where(getattr(AuditLog, column) == value)
    return list(db.scalars(stmt).all())


def set_cookie_headers(response) -> list[str]:
    return response.headers.get_list("set-cookie")


def cookie_header(response, name: str, *, deleted: bool, path: str) -> str:
    """The Set-Cookie header for a cookie name and path, either setting or deleting it."""
    for header in set_cookie_headers(response):
        attributes = [part.strip() for part in header.split(";")]
        cookie_name, _, value = attributes[0].partition("=")
        is_deletion = value in ("", '""') or "max-age=0" in (a.lower() for a in attributes)
        if cookie_name == name and is_deletion == deleted and f"Path={path}" in attributes:
            return header
    raise AssertionError(
        f"No Set-Cookie for {name} (deleted={deleted}, path={path}): {set_cookie_headers(response)}"
    )


def create_org(client: TestClient, label: str, suffix: str, name: str | None = None):
    """POST an organization named '<label> <suffix>' (or name) with slug '<label>-<suffix>'."""
    payload = {"name": name or f"{label} {suffix}", "slug": f"{label.lower()}-{suffix}"}
    return client.post("/api/v1/organizations", json=payload)


@pytest.fixture
def rate_limited(monkeypatch):
    """Enable rate limiting with fresh in-process counters, frozen inside one window."""
    frozen = 1_800_000_000.0  # start of a minute: the whole test runs in one window
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(rate_limit, "get_redis_safe", lambda: None)
    # Replaces the module reference inside rate_limit only; the real clock is untouched.
    monkeypatch.setattr(rate_limit, "time", SimpleNamespace(time=lambda: frozen))
    reset_rate_limits()
    yield
    reset_rate_limits()


# ── Lockout ───────────────────────────────────────────────────────────────────

def test_expired_lock_starts_a_new_failure_count(db):
    client = TestClient(app)
    email = register(client)
    user = load_user(db, email)
    user.failed_login_attempts = 5
    user.locked_until = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()

    assert login(client, email, "Wrong-Password-1234").status_code == 401
    user = load_user(db, email)
    assert user.failed_login_attempts == 1
    assert user.locked_until is None
    assert not user.is_locked

    assert login(client, email).status_code == 200
    user = load_user(db, email)
    assert user.failed_login_attempts == 0
    assert user.last_login_at is not None


def test_locked_and_unknown_accounts_get_the_same_answer(db):
    client = TestClient(app)
    email = register(client)
    user = load_user(db, email)
    user.locked_until = datetime.now(UTC) + timedelta(minutes=10)
    db.commit()

    locked = login(client, email)  # correct password, but the account is locked
    unknown = login(client, new_email("unknown"))
    assert locked.status_code == unknown.status_code == 401
    assert locked.json() == unknown.json() == {"detail": GENERIC_LOGIN_ERROR}
    # Attempts against a locked account do not extend the count.
    assert load_user(db, email).failed_login_attempts == 0
    failures = audit_entries(db, "auth.login_failed", actor_id=user.id)
    assert [e.metadata_.get("reason") for e in failures] == ["account_locked"]


def test_lockout_is_audited_exactly_once(db):
    client = TestClient(app)
    email = register(client)
    for _ in range(7):
        response = login(client, email, "Wrong-Password-1234")
        assert response.status_code == 401
        assert response.json()["detail"] == GENERIC_LOGIN_ERROR
    user = load_user(db, email)
    assert user.is_locked
    assert user.failed_login_attempts == 5
    locked = audit_entries(db, "auth.account_locked", actor_id=user.id)
    assert len(locked) == 1
    assert locked[0].metadata_["failed_attempts"] == 5
    failures = audit_entries(db, "auth.login_failed", actor_id=user.id)
    reasons = sorted(e.metadata_["reason"] for e in failures)
    assert reasons == ["account_locked"] * 2 + ["invalid_password"] * 5


def test_lock_applied_during_verification_is_not_undone_by_a_correct_login(db, monkeypatch):
    client = TestClient(app)
    email = register(client)
    user_id = load_user(db, email).id

    def verify_while_another_request_locks(stored_hash, plain):
        # Simulates a concurrent request reaching the threshold mid-verification.
        locked_until = datetime.now(UTC) + timedelta(minutes=15)
        with SessionLocal() as other:
            other.execute(
                update(User).where(User.id == user_id)
                .values(failed_login_attempts=5, locked_until=locked_until)
            )
            other.commit()
        return verify_password(stored_hash, plain)

    monkeypatch.setattr(auth_service, "verify_password", verify_while_another_request_locks)
    response = login(client, email)
    assert response.status_code == 401
    assert response.json()["detail"] == GENERIC_LOGIN_ERROR
    assert client.cookies.get("access_token") is None
    user = load_user(db, email)
    assert user.is_locked and user.failed_login_attempts == 5


def test_login_upgrades_an_outdated_hash_and_binds_the_session_to_it(db):
    weak_hasher = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    user = User(
        email=new_email("rehash"), display_name="Rehash Tester",
        password_hash=weak_hasher.hash(PASSWORD),
    )
    db.add(user)
    db.commit()
    old_hash = user.password_hash
    assert needs_rehash(old_hash)

    client = TestClient(app)
    assert login(client, user.email).status_code == 200
    upgraded = load_user(db, user.email)
    assert upgraded.password_hash != old_hash
    assert not needs_rehash(upgraded.password_hash)
    # The new session belongs to the upgraded hash, so it keeps working.
    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.post("/api/v1/auth/refresh").status_code == 200


# ── Sessions bound to the password ────────────────────────────────────────────

def test_password_change_ends_other_sessions_but_not_the_callers(db):
    client, email = signed_in_client()
    other = TestClient(app)
    assert login(other, email).status_code == 200
    assert other.get("/api/v1/auth/me").status_code == 200

    response = client.post("/api/v1/auth/change-password", json={
        "current_password": PASSWORD, "new_password": NEW_PASSWORD,
    })
    assert response.status_code == 204, response.text
    cookie_header(response, "access_token", deleted=False, path="/")
    cookie_header(response, "refresh_token", deleted=False, path="/api/v1/auth")

    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.post("/api/v1/auth/refresh").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200

    me = other.get("/api/v1/auth/me")
    assert me.status_code == 401
    assert me.json()["detail"] == SESSION_INVALID
    refresh = other.post("/api/v1/auth/refresh")
    assert refresh.status_code == 401
    assert refresh.json()["detail"] == SESSION_INVALID

    assert login(other, email).status_code == 401
    assert login(other, email, NEW_PASSWORD).status_code == 200
    user = load_user(db, email)
    assert len(audit_entries(db, "auth.password_change", actor_id=user.id)) == 1


def test_password_change_rejects_same_or_weak_password(db):
    client, email = signed_in_client()
    same = client.post("/api/v1/auth/change-password", json={
        "current_password": PASSWORD, "new_password": PASSWORD,
    })
    assert same.status_code == 422
    assert same.json()["detail"] == "New password must differ from the current password"

    local_part = email.split("@")[0]
    weak = client.post("/api/v1/auth/change-password", json={
        "current_password": PASSWORD, "new_password": f"{local_part}-2026",
    })
    assert weak.status_code == 422
    assert "email" in weak.json()["detail"]

    too_short = client.post("/api/v1/auth/change-password", json={
        "current_password": PASSWORD, "new_password": "Short-2026!",
    })
    assert too_short.status_code == 422

    # Nothing changed: the session and the old password still work.
    assert client.get("/api/v1/auth/me").status_code == 200
    assert login(TestClient(app), email).status_code == 200


@pytest.mark.parametrize("make_password", [
    pytest.param(lambda email: "Abcdefgh12!", id="eleven-characters"),
    pytest.param(lambda email: email.split("@")[0] + "-Secret!", id="contains-email-name"),
    pytest.param(lambda email: "Password1234", id="common-password"),
])
def test_weak_registrations_are_rejected(db, make_password):
    email = new_email("weak")
    response = TestClient(app).post("/api/v1/auth/register", json={
        "email": email, "password": make_password(email), "full_name": "Weak Password",
    })
    assert response.status_code == 422, response.text
    db.expire_all()
    assert db.scalars(select(User).where(User.email == email)).first() is None


@pytest.mark.parametrize("password", ["Password1234", "Zq7#xv"], ids=["policy", "field"])
def test_validation_errors_never_echo_the_submitted_password(password):
    response = TestClient(app).post("/api/v1/auth/register", json={
        "email": new_email("echo"), "password": password, "full_name": "Echo Check",
    })
    assert response.status_code == 422
    assert password not in response.text
    for issue in response.json()["detail"]:
        assert "msg" in issue and "loc" in issue
        assert "input" not in issue and "ctx" not in issue


# ── Single-use refresh tokens ─────────────────────────────────────────────────

def test_refresh_token_reuse_is_rejected_and_audited(db):
    client, email = signed_in_client()
    used_refresh = client.cookies["refresh_token"]
    assert client.post("/api/v1/auth/refresh").status_code == 200

    replay = TestClient(app).post(
        "/api/v1/auth/refresh", headers={"Cookie": f"refresh_token={used_refresh}"}
    )
    assert replay.status_code == 401
    assert replay.json()["detail"] == "Refresh token has already been used. Please log in again."

    user = load_user(db, email)
    reuse = audit_entries(db, "auth.refresh_reuse", actor_id=user.id)
    assert len(reuse) == 1
    # The legitimate holder of the rotated token is unaffected.
    assert client.post("/api/v1/auth/refresh").status_code == 200


# ── Cookies ───────────────────────────────────────────────────────────────────

def test_refresh_cookie_is_scoped_to_auth_and_logout_clears_every_copy(db):
    client = TestClient(app)
    email = register(client)
    response = login(client, email)
    assert response.status_code == 200

    refresh = cookie_header(response, "refresh_token", deleted=False, path="/api/v1/auth")
    assert "samesite=strict" in refresh.lower()
    assert "httponly" in refresh.lower()
    access = cookie_header(response, "access_token", deleted=False, path="/")
    assert "samesite=lax" in access.lower()
    # A refresh cookie left at '/' by an earlier version is removed.
    cookie_header(response, "refresh_token", deleted=True, path="/")
    # Exactly one refresh cookie in the jar: no CookieConflict.
    assert client.cookies["refresh_token"]

    user = load_user(db, email)
    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 204
    cookie_header(logout, "refresh_token", deleted=True, path="/api/v1/auth")
    cookie_header(logout, "refresh_token", deleted=True, path="/")
    cookie_header(logout, "access_token", deleted=True, path="/")
    assert client.cookies.get("refresh_token") is None
    assert client.cookies.get("access_token") is None
    assert len(audit_entries(db, "auth.logout", actor_id=user.id)) == 1


def test_logout_without_a_valid_session_still_succeeds():
    client = TestClient(app)
    client.cookies.set("access_token", "not-a-jwt")
    assert client.post("/api/v1/auth/logout").status_code == 204


# ── Rate limits ───────────────────────────────────────────────────────────────

def test_eleventh_login_in_a_minute_is_rate_limited(rate_limited):
    client = TestClient(app)
    for _ in range(10):
        assert login(client, new_email("ratelimit")).status_code == 401
    response = login(client, new_email("ratelimit"))
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1


def test_login_limit_per_account_applies_across_addresses(rate_limited, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT", "3/minute")
    monkeypatch.setattr(settings, "TRUSTED_PROXY_HOPS", 1)
    client = TestClient(app)
    email = new_email("ratelimit-account")
    for index in range(3):
        forwarded = {"X-Forwarded-For": f"198.51.100.{index + 1}"}
        assert login(client, email, headers=forwarded).status_code == 401
    response = login(client, email, headers={"X-Forwarded-For": "198.51.100.200"})
    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_registration_and_password_changes_are_rate_limited(rate_limited, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "REGISTER_RATE_LIMIT", "1/hour")
    monkeypatch.setattr(settings, "PASSWORD_CHANGE_RATE_LIMIT", "1/minute")
    monkeypatch.setattr(settings, "LOGIN_RATE_LIMIT", "100/minute")
    client = TestClient(app)
    email = register(client)
    second = client.post("/api/v1/auth/register", json={
        "email": new_email(), "password": PASSWORD, "full_name": "Second Account",
    })
    assert second.status_code == 429

    assert login(client, email).status_code == 200
    wrong = {"current_password": "Not-The-Password-2026", "new_password": NEW_PASSWORD}
    assert client.post("/api/v1/auth/change-password", json=wrong).status_code == 401
    assert client.post("/api/v1/auth/change-password", json=wrong).status_code == 429


# ── Registration and organization controls ────────────────────────────────────

def test_disabled_self_registration_allows_only_superusers(db, monkeypatch):
    member, _member_email = signed_in_client()
    admin, superuser = create_superuser(db)
    monkeypatch.setattr(get_settings(), "ALLOW_SELF_REGISTRATION", False)

    payload = {"email": new_email("invited"), "password": PASSWORD, "full_name": "Invited User"}
    anonymous = TestClient(app).post("/api/v1/auth/register", json=payload)
    assert anonymous.status_code == 403
    assert anonymous.json()["detail"] == (
        "Self-registration is disabled. Ask a platform administrator to create your account."
    )
    assert member.post("/api/v1/auth/register", json=payload).status_code == 403

    created = admin.post("/api/v1/auth/register", json=payload)
    assert created.status_code == 201, created.text
    entries = audit_entries(db, "auth.register", object_id=created.json()["id"])
    assert len(entries) == 1
    assert entries[0].actor_id == superuser.id
    assert entries[0].metadata_["created_by_superuser"] is True
    assert login(TestClient(app), payload["email"]).status_code == 200


def test_self_registration_is_audited_with_the_new_user_as_actor(db):
    email = register(TestClient(app))
    user = load_user(db, email)
    entries = audit_entries(db, "auth.register", object_id=str(user.id))
    assert len(entries) == 1 and entries[0].actor_id == user.id


def test_organization_creation_can_be_limited_to_superusers(db, monkeypatch):
    client, _email = signed_in_client()
    admin, _superuser = create_superuser(db)
    monkeypatch.setattr(get_settings(), "ORG_CREATION", "superuser")
    suffix = uuid.uuid4().hex[:12]
    payload = {"name": f"Restricted {suffix}", "slug": f"restricted-{suffix}"}

    response = client.post("/api/v1/organizations", json=payload)
    assert response.status_code == 403
    assert response.json()["detail"] == "Only platform administrators can create organizations."
    assert admin.post("/api/v1/organizations", json=payload).status_code == 201


def test_duplicate_organization_names_conflict_on_create_and_rename():
    client, _email = signed_in_client()
    suffix = uuid.uuid4().hex[:12]
    taken = f"Taken {suffix}"
    assert create_org(client, "Taken", suffix).status_code == 201

    duplicate = create_org(client, "Other", suffix, name=taken)
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == f"Organization name '{taken}' is already taken"

    second = create_org(client, "Second", suffix)
    assert second.status_code == 201
    url = f"/api/v1/organizations/{second.json()['id']}"
    rename = client.patch(url, json={"name": f"  {taken} "})
    assert rename.status_code == 409
    assert rename.json()["detail"] == f"Organization name '{taken}' is already taken"
    # Keeping its own name, or choosing a free one, is fine.
    assert client.patch(url, json={"name": f"Second {suffix}"}).status_code == 200
    renamed = client.patch(url, json={"name": f"Renamed {suffix}"})
    assert renamed.status_code == 200
    assert renamed.json()["name"] == f"Renamed {suffix}"
    assert client.patch(url, json={"name": "   "}).status_code == 422


def test_add_member_writes_member_added_audit(db):
    admin, _admin_email = signed_in_client()
    member_email = register(TestClient(app))
    suffix = uuid.uuid4().hex[:12]
    org = create_org(admin, "Members", suffix)
    assert org.status_code == 201
    org_id = org.json()["id"]

    response = admin.post(
        f"/api/v1/organizations/{org_id}/members", json={"email": member_email, "role": "viewer"}
    )
    assert response.status_code == 201, response.text
    member = response.json()
    assert member["email"] == member_email and member["role"] == "viewer"

    entries = audit_entries(db, "org.member_added", object_id=member["id"])
    assert len(entries) == 1
    assert str(entries[0].organization_id) == org_id
    assert entries[0].metadata_["role"] == "viewer"
    assert entries[0].metadata_["member_user_id"] == member["user_id"]
    assert not audit_entries(db, "user.assign_role", object_id=member["id"])


def test_me_loads_memberships_without_a_query_per_row(query_counter):
    client, _email = signed_in_client()
    suffix = uuid.uuid4().hex[:12]

    def statements_for_me(expected_memberships: int) -> int:
        query_counter.reset()
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 200
        assert len(response.json()["memberships"]) == expected_memberships
        return query_counter.count

    assert create_org(client, "One", suffix).status_code == 201
    with_one = statements_for_me(1)
    for label in ("Two", "Three"):
        assert create_org(client, label, suffix).status_code == 201
    with_three = statements_for_me(3)
    assert with_three == with_one
    assert with_three <= 2


def test_unknown_email_failure_is_audited_without_actor(db):
    """A failed login for an unknown email records the address but no actor id."""
    email = new_email("nobody")
    assert login(TestClient(app), email).status_code == 401
    db.expire_all()
    count = db.scalar(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.action == "auth.login_failed",
            AuditLog.metadata_["actor_email"].as_string() == email,
            AuditLog.actor_id.is_(None),
        )
    )
    assert count == 1
