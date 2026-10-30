"""Verify that frontend static files are served at root."""

from fastapi.testclient import TestClient

from app.main import app


def test_frontend_index_served():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "VulnScanner" in response.text
    assert "text/html" in response.headers.get("content-type", "")


def test_frontend_static_assets_served():
    client = TestClient(app)
    css_resp = client.get("/styles.css")
    assert css_resp.status_code == 200
    assert "cyber-theme" in css_resp.text

    js_resp = client.get("/app.js")
    assert js_resp.status_code == 200
    assert "initApplication" in js_resp.text
