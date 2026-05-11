import importlib
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def security_app(tmp_path, monkeypatch):
    db_path = tmp_path / "security.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path.as_posix()}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://safescan-qr.onrender.com,http://localhost:5173")
    monkeypatch.setenv("ADMIN_EMAILS", "admin@example.com")
    monkeypatch.setenv("OWNER_EMAILS", "owner@example.com")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")

    sys.modules.pop("hackabull", None)
    sys.modules.pop("db", None)
    module = importlib.import_module("hackabull")
    module.RATE_LIMITS.clear()
    module.run_fraud_checks = lambda *args, **kwargs: []

    yield module, TestClient(module.qr_app, base_url="https://testserver"), db_path

    sys.modules.pop("hackabull", None)
    sys.modules.pop("db", None)


def register(client, email, password="password123"):
    return client.post("/auth/register", data={"email": email, "password": password}, follow_redirects=False)


def add_scan(db_path, email, url):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at)
            VALUES (?, ?, ?, 12, 'SAFE', '[]', 0, ?)
            """,
            (f"scan_{email.split('@')[0]}", email, url, f"2026-05-10T12:00:0{len(url) % 9}Z"),
        )


def test_security_headers_are_present_on_health_response(security_app):
    module, client, _ = security_app

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Server" not in response.headers


def test_api_responses_are_no_store(security_app):
    _, client, _ = security_app

    response = client.get("/api/app-runtime")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_cors_allows_only_configured_origins(security_app):
    _, client, _ = security_app
    headers = {
        "Origin": "https://safescan-qr.onrender.com",
        "Access-Control-Request-Method": "POST",
    }

    allowed = client.options("/api/scan", headers=headers)
    denied = client.options(
        "/api/scan",
        headers={**headers, "Origin": "https://evil.com"},
    )
    state_change = client.post(
        "/api/analyze",
        headers={"Origin": "https://evil.com"},
        json={"url": "https://example.com"},
    )

    assert allowed.status_code == 200
    assert allowed.headers["Access-Control-Allow-Origin"] == "https://safescan-qr.onrender.com"
    assert denied.status_code in (400, 403)
    assert "Access-Control-Allow-Origin" not in denied.headers
    assert state_change.status_code == 403


def test_session_cookie_uses_host_prefix(security_app):
    module, client, _ = security_app

    response = register(client, "cookie@example.com")

    assert response.status_code in (200, 303)
    assert module.SESSION_COOKIE_NAME == "__Host-safescan_session"
    assert "__Host-safescan_session" in client.cookies
    set_cookie = response.headers.get("set-cookie", "")
    assert "__Host-safescan_session=" in set_cookie
    assert "Secure" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "SameSite=strict" in set_cookie


def test_scan_history_rls_isolates_regular_users(security_app):
    _, client, db_path = security_app
    register(client, "user-a@example.com")
    add_scan(db_path, "user-a@example.com", "https://a.example")
    add_scan(db_path, "user-b@example.com", "https://b.example")

    response = client.get("/api/scan-history")

    assert response.status_code == 200
    urls = [row["url"] for row in response.json()]
    assert urls == ["https://a.example"]


def test_scan_history_rls_allows_admin_to_see_all_rows(security_app):
    _, client, db_path = security_app
    register(client, "admin@example.com")
    add_scan(db_path, "user-a@example.com", "https://a.example")
    add_scan(db_path, "user-b@example.com", "https://b.example")

    response = client.get("/api/scan-history")

    assert response.status_code == 200
    urls = {row["url"] for row in response.json()}
    assert urls == {"https://a.example", "https://b.example"}


def test_unauthenticated_scan_history_returns_401(security_app):
    _, client, _ = security_app

    response = client.get("/api/scan-history")

    assert response.status_code == 401
