"""Session regressions using real hashing, cookies, and the test database."""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import create_access_token
from app.main import app
from app.models.audit import AuditLog


def registered_client():
    client = TestClient(app)
    email = f"session-{uuid.uuid4().hex}@example.com"
    password = "SessionPassword123!"
    response = client.post("/api/v1/auth/register", json={
        "email": email, "password": password, "full_name": "Session Tester",
    })
    assert response.status_code == 201
    return client, email, password


def test_refresh_logout_and_password_change(db):
    client, email, password = registered_client()
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    assert response.json()["expires_in"] == 3600
    assert client.cookies["access_token"] == response.json()["access_token"]
    assert "HttpOnly" in response.headers["set-cookie"]
    first_refresh = client.cookies["refresh_token"]
    response = client.post("/api/v1/auth/refresh")
    assert response.status_code == 200
    assert client.cookies["refresh_token"] != first_refresh
    assert client.get("/api/v1/auth/me").status_code == 200
    new_password = "ChangedPassword123!"
    assert client.post("/api/v1/auth/change-password", json={
        "current_password": password, "new_password": new_password,
    }).status_code == 204
    assert client.post("/api/v1/auth/logout").status_code == 204
    assert client.get("/api/v1/auth/me").status_code == 401
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": email, "password": new_password}
        ).status_code
        == 200
    )
    actions = db.scalars(
        select(AuditLog).where(AuditLog.metadata_["actor_email"].as_string() == email)
    ).all()
    assert {entry.action for entry in actions} >= {
        "auth.login",
        "auth.login_failed",
        "auth.password_change",
    }


def test_lockout_blocks_login_but_not_existing_session():
    client, email, password = registered_client()
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code
        == 200
    )
    # Wrong guesses from elsewhere lock password logins, not the session already signed in.
    attacker = TestClient(app)
    for _ in range(5):
        assert (
            attacker.post(
                "/api/v1/auth/login", json={"email": email, "password": "incorrect"}
            ).status_code
            == 401
        )
    locked = attacker.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert locked.status_code == 401
    assert locked.json()["detail"] == "Invalid email or password"
    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.post("/api/v1/auth/refresh").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200


def test_malformed_signed_subject_is_rejected():
    client = TestClient(app)
    client.cookies.set("access_token", create_access_token("invalid-uuid"))
    assert client.get("/api/v1/auth/me").status_code == 401


def test_token_revocation_on_logout_and_bearer_auth():
    client, email, password = registered_client()
    resp = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    token = resp.json()["access_token"]

    # Verify Bearer header works on a fresh client without cookies
    bearer_client = TestClient(app)
    me_resp = bearer_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["email"] == email

    # Logout on the original client (which has the cookie)
    logout_resp = client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 204

    # The revoked token should now fail even with Bearer header
    revoked_resp = bearer_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert revoked_resp.status_code == 401
    assert "revoked" in revoked_resp.json()["detail"].lower()


def test_refresh_token_cannot_be_replayed(db):
    client, email, password = registered_client()
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code
        == 200
    )
    used_refresh = client.cookies["refresh_token"]
    assert client.post("/api/v1/auth/refresh").status_code == 200
    replay = TestClient(app)
    replay.cookies.set("refresh_token", used_refresh)
    assert replay.post("/api/v1/auth/refresh").status_code == 401


def test_last_admin_cannot_leave_or_be_demoted(db):
    client, email, password = registered_client()
    assert (
        client.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code
        == 200
    )
    suffix = uuid.uuid4().hex[:8]
    org = client.post(
        "/api/v1/organizations", json={"name": f"Org {suffix}", "slug": f"org-{suffix}"}
    )
    assert org.status_code == 201
    user_id = client.get("/api/v1/auth/me").json()["id"]
    member_url = f"/api/v1/organizations/{org.json()['id']}/members/{user_id}"
    assert client.patch(member_url, json={"role": "viewer"}).status_code == 409
    assert client.delete(member_url).status_code == 409
