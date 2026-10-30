"""Integration tests for authentication flow."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_login_and_me_flow(client):
    # 1. Register user
    email = "security_lead@example.com"
    reg_res = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "full_name": "Security Lead",
        },
    )
    assert reg_res.status_code in (201, 409)  # 409 if already exists

    # 2. Login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "StrongPassword123!"},
    )
    assert login_res.status_code == 200
    assert "access_token" in login_res.cookies or "access_token" in login_res.json()

    # 3. Access current user profile
    me_res = client.get("/api/v1/auth/me")
    assert me_res.status_code == 200
    data = me_res.json()
    assert data["email"] == email


def test_login_bad_credentials(client):
    res = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@example.com", "password": "WrongPassword!"},
    )
    assert res.status_code == 401
