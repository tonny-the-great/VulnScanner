"""Startup seeding, security headers, readiness, auditing and platform endpoints."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app.config import get_settings
from app.core.audit import audit_log
from app.core.security import hash_password
from app.core.security_headers import CONSOLE_CSP
from app.database import get_db
from app.main import (
    app,
    create_app,
    log_configuration_warnings,
    seed_database,
    sync_system_profiles,
)
from app.models.audit import AuditLog
from app.models.finding import Finding, ScanFinding, finding_seen_in_scan
from app.models.scan import ScanProfile
from app.models.user import User
from app.scanning.orchestrator import ScanOrchestrator
from app.scanning.profiles import DEFAULT_PROFILES

PASSWORD = "FoundationPassword-2026!"


def signed_in_client(**client_kwargs):
    client = TestClient(app, **client_kwargs)
    email = f"foundation-{uuid.uuid4().hex}@example.com"
    assert client.post("/api/v1/auth/register", json={
        "email": email, "password": PASSWORD, "full_name": "Foundation Tester",
    }).status_code == 201
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).status_code
        == 200
    )
    return client, email


def test_profile_sync_updates_config_and_keeps_operator_disable(db):
    sync_system_profiles(db)
    stmt = select(ScanProfile).where(
        ScanProfile.name == "fast_discovery", ScanProfile.organization_id.is_(None)
    )
    profile = db.scalars(stmt).first()
    expected = next(p for p in DEFAULT_PROFILES if p["name"] == "fast_discovery")
    profile.config_json = {"nmap": {"scripts": ["all"]}}
    profile.description = "Outdated description"
    profile.is_enabled = False
    db.commit()
    try:
        changed = sync_system_profiles(db)
        db.expire_all()
        profile = db.scalars(stmt).first()
        assert "fast_discovery" in changed
        assert profile.config_json == expected["config_json"]
        assert profile.description == expected["description"]
        assert profile.is_enabled is False
        # Nothing left to change on a second run.
        assert "fast_discovery" not in sync_system_profiles(db)
    finally:
        profile.is_enabled = True
        db.commit()


def test_profile_sync_leaves_other_system_profiles_alone(db):
    custom = ScanProfile(
        name=f"custom-{uuid.uuid4().hex}", display_name="Operator profile", config_json={"nmap": {}}
    )
    db.add(custom)
    db.commit()
    sync_system_profiles(db)
    db.refresh(custom)
    assert custom.is_enabled is True
    assert custom.config_json == {"nmap": {}}


def test_bootstrap_superuser_email_is_normalized(db, monkeypatch):
    email = f"Boot.Strap-{uuid.uuid4().hex[:8]}@Example.COM"
    password = "Platform-Bootstrap-Secret-2026!"
    monkeypatch.setattr(get_settings(), "FIRST_SUPERUSER_EMAIL", f"  {email} ")
    monkeypatch.setattr(get_settings(), "FIRST_SUPERUSER_PASSWORD", password)
    seed_database()
    user = db.scalars(select(User).where(User.email == email.lower())).first()
    assert user is not None and user.is_superuser
    client = TestClient(app)
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code
        == 200
    )
    # Running the seed again neither fails nor duplicates the account.
    seed_database()
    assert len(db.scalars(select(User).where(User.email == email.lower())).all()) == 1


def test_bootstrap_superuser_with_weak_password_is_not_created(db, monkeypatch):
    email = f"weak-{uuid.uuid4().hex[:8]}@example.com"
    monkeypatch.setattr(get_settings(), "FIRST_SUPERUSER_EMAIL", email)
    monkeypatch.setattr(get_settings(), "FIRST_SUPERUSER_PASSWORD", "short")
    seed_database()
    assert db.scalars(select(User).where(User.email == email)).first() is None


def test_security_headers_on_console_and_api():
    client = TestClient(app)
    console = client.get("/")
    assert console.status_code == 200
    assert console.headers["content-security-policy"] == CONSOLE_CSP
    assert console.headers["x-content-type-options"] == "nosniff"
    assert console.headers["x-frame-options"] == "DENY"
    assert console.headers["referrer-policy"] == "same-origin"
    assert "strict-transport-security" not in console.headers  # not production

    api = client.get("/api/v1/auth/me")
    assert api.status_code == 401
    assert api.headers["cache-control"] == "no-store"
    assert api.headers["x-content-type-options"] == "nosniff"
    assert "content-security-policy" not in api.headers


def test_frontend_test_harness_is_not_served():
    client = TestClient(app)
    assert client.get("/tests/harness.cjs").status_code == 404
    assert client.get("/tests/fixtures/contracts.json").status_code == 404
    assert client.get("/TESTS/harness.cjs").status_code == 404
    assert client.get("/app.js").status_code == 200


def test_docs_are_disabled_in_production(monkeypatch):
    assert TestClient(app).get("/openapi.json").status_code == 200  # testing default
    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "production")
    production = TestClient(create_app())
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert production.get(path).status_code == 404, path
    health = production.get("/health")
    assert health.status_code == 200
    assert health.headers["strict-transport-security"] == "max-age=31536000"


def test_duplicate_organization_name_returns_conflict():
    client, _email = signed_in_client()
    name = f"Duplicate {uuid.uuid4().hex}"
    first = client.post(
        "/api/v1/organizations", json={"name": name, "slug": f"dup-{uuid.uuid4().hex[:12]}"}
    )
    assert first.status_code == 201, first.text
    second = client.post(
        "/api/v1/organizations", json={"name": name, "slug": f"dup-{uuid.uuid4().hex[:12]}"}
    )
    assert second.status_code == 409, second.text
    # No SQL or parameters leak into the response.
    assert "INSERT" not in second.text and "UNIQUE" not in second.text


def test_readiness_reports_database_and_redis():
    response = TestClient(app).get("/health/ready")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready" and body["database"] == "ok"
    assert body["redis"] in ("ok", "unavailable")


def test_readiness_fails_when_database_is_down():
    class BrokenSession:
        def execute(self, *args, **kwargs):
            raise OperationalError("SELECT 1", {}, Exception("connection refused by db-host:5432"))

    def broken_db():
        yield BrokenSession()

    app.dependency_overrides[get_db] = broken_db
    try:
        response = TestClient(app).get("/health/ready")
    finally:
        app.dependency_overrides.pop(get_db, None)
    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["database"] == "unavailable"
    assert "refused" not in response.text and "db-host" not in response.text


def test_readiness_requires_redis_in_production(monkeypatch):
    monkeypatch.setattr("app.routers.system.get_redis_safe", lambda: None)
    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "production")
    response = TestClient(app).get("/health/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready", "database": "ok", "redis": "unavailable"}


def test_uncommitted_audit_entry_is_rolled_back_with_its_action(db):
    marker = uuid.uuid4().hex
    audit_log(db, commit=False, action="test.uncommitted", resource_type="test", resource_id=marker)
    db.rollback()
    assert db.scalars(select(AuditLog).where(AuditLog.object_id == marker)).first() is None
    audit_log(db, commit=False, action="test.committed", resource_type="test", resource_id=marker)
    db.commit()
    assert (
        db.scalars(select(AuditLog).where(AuditLog.object_id == marker)).one().action
        == "test.committed"
    )


def test_audit_entries_record_request_context(db):
    client, _email = signed_in_client(headers={"User-Agent": "foundation-audit-agent/1.0"})
    response = client.post("/api/v1/organizations", json={
        "name": f"Audit context {uuid.uuid4().hex}", "slug": f"audit-{uuid.uuid4().hex[:12]}",
    })
    assert response.status_code == 201, response.text
    entry = db.scalars(select(AuditLog).where(
        AuditLog.action == "org.created", AuditLog.object_id == response.json()["id"],
    )).one()
    assert entry.user_agent == "foundation-audit-agent/1.0"
    assert entry.ip_address == "testclient"


def test_platform_audit_log_is_for_superusers_only(db):
    client, _email = signed_in_client()
    assert client.get("/api/v1/audit-log").status_code == 403

    email = f"platform-admin-{uuid.uuid4().hex}@example.com"
    db.add(
        User(
            email=email,
            display_name="Platform Admin",
            password_hash=hash_password(PASSWORD),
            is_superuser=True,
        )
    )
    db.commit()
    admin = TestClient(app)
    assert (
        admin.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD}).status_code
        == 200
    )
    response = admin.get("/api/v1/audit-log", params={"action": "auth.login", "limit": 5})
    assert response.status_code == 200, response.text
    entries = response.json()
    assert entries and len(entries) <= 5
    assert all(
        entry["organization_id"] is None and entry["action"] == "auth.login" for entry in entries
    )
    assert admin.get("/api/v1/audit-log", params={"limit": 500}).status_code == 422


def test_finding_seen_in_scan_uses_history_and_fallbacks(workflow, launch_scan, db):
    first_scan = launch_scan(workflow)
    ScanOrchestrator(db, first_scan).run_scan()
    # Legacy fallback: a scan without scan_findings rows matches via first/last scan ids.
    seen = db.scalars(select(Finding).where(finding_seen_in_scan(first_scan))).all()
    assert len(seen) == 1
    finding = seen[0]

    # A sighting recorded only in scan_findings (here: a scan in between) also matches.
    other_scan = launch_scan(workflow)
    assert not db.scalars(select(Finding).where(finding_seen_in_scan(other_scan))).all()
    db.add(ScanFinding(scan_id=other_scan, finding_id=finding.id))
    db.commit()
    assert [f.id for f in db.scalars(select(Finding).where(finding_seen_in_scan(other_scan)))] == [
        finding.id
    ]
    assert (
        db.scalars(select(ScanFinding).where(ScanFinding.scan_id == other_scan))
        .one()
        .seen_at.tzinfo
        is not None
    )


def test_query_counter_counts_statements_from_requests(query_counter):
    assert TestClient(app).get("/health/ready").status_code == 200
    assert query_counter.count >= 1
    assert any("SELECT 1" in statement for statement in query_counter.statements)
    query_counter.reset()
    assert query_counter.count == 0 and query_counter.statements == []


def test_configuration_warnings_flag_open_production_setup(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "CORS_ORIGINS", "http://console.example.com")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    warnings = " | ".join(log_configuration_warnings())
    assert "CORS_ORIGINS" in warnings
    assert "SQLite" in warnings
    assert "Self-registration" in warnings
    assert "RATE_LIMIT_ENABLED" in warnings
