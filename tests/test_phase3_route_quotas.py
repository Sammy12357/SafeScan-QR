"""Phase 3 public-route budgets, including the HTML and mobile entry points."""

import importlib
import re
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient as RawTestClient

from browser_client import BrowserTestClient as TestClient


@pytest.fixture()
def quota_app(tmp_path, monkeypatch):
    db_path = tmp_path / "quotas.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    auth = importlib.import_module("hackabull.routes_scan_auth")
    auth.LOCAL_AUTH_ENABLED = True
    auth.run_fraud_checks = lambda *args, **kwargs: []
    app.RATE_LIMITS.clear()
    yield app, TestClient(app.qr_app, base_url="https://testserver"), db_path, monkeypatch
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def assert_limited(response):
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 0


def assert_html_limited(response):
    assert_limited(response)
    assert response.headers["content-type"].startswith("text/html")
    assert "Too many requests" in response.text


def edge_ip(index):
    return {"CF-Connecting-IP": f"203.0.113.{index}"}


def google_login_for_quota(client, auth, monkeypatch, *, subject, email, ip_index):
    # Each browser sign-in needs its own server challenge and GIS double-submit
    # token. Clear the previous session so /login can issue a fresh challenge.
    client.cookies.clear()
    page = client.get("/login")
    assert page.status_code == 200
    match = re.search(r'data-nonce="([A-Za-z0-9_-]+)"', page.text)
    assert match
    monkeypatch.setattr(auth.id_token, "verify_oauth2_token", lambda *_: {
        "sub": subject, "email": email, "email_verified": True,
        "nonce": match.group(1),
    })
    client.cookies.set("g_csrf_token", "quota-test-gis-token")
    return client.post(
        "/auth/google",
        data={"credential": "valid", "g_csrf_token": "quota-test-gis-token", "next": "/profile"},
        headers=edge_ip(ip_index),
        follow_redirects=False,
    )


def test_guest_scan_budget_is_shared_by_html_and_json(quota_app):
    _, client, _, _ = quota_app
    for _ in range(10):
        response = client.post("/search_qr_api", data={"manual_url": "WIFI:T:WPA;S:Cafe;P:test;;"})
        assert response.status_code == 200
    assert_limited(client.post("/api/analyze", json={"url": "https://example.com"}))
    assert_html_limited(client.post("/search_qr_api", data={"manual_url": "WIFI:T:WPA;S:Cafe;P:test;;"}))


def test_signed_in_scan_budget_is_shared_by_text_and_file(quota_app):
    _, client, _, _ = quota_app
    assert client.post("/auth/register", data={"email": "scanner@example.com", "password": "password123"}).status_code == 200
    for _ in range(30):
        # Rejected oversized payloads still consume capacity before analysis.
        assert client.post("/api/scan", json={"payload": "A" * 4097}).status_code == 400
    assert_limited(client.post("/api/scan/file", files={"file": ("qr.png", b"not-an-image", "image/png")}))


def test_signed_in_scan_budget_covers_legacy_html_and_analyze_routes(quota_app):
    _, client, _, _ = quota_app
    assert client.post("/auth/register", data={"email": "scanner@example.com", "password": "password123"}).status_code == 200
    for _ in range(30):
        assert client.post("/api/scan", json={"payload": "A" * 4097}).status_code == 400

    assert_html_limited(client.post("/search_qr_api", data={"manual_url": "WIFI:T:WPA;S:Cafe;P:test;;"}))
    assert_limited(client.post("/api/analyze", json={"url": "https://example.com"}))


def test_consent_budget_limits_database_writes(quota_app):
    _, client, db_path, _ = quota_app
    for _ in range(10):
        assert client.post("/api/consent", json={"consentType": "essential_only"}).status_code == 200
    assert_limited(client.post("/api/consent", json={"consentType": "essential_only"}))
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM consent_logs").fetchone()[0] == 10


def test_reports_share_ten_per_hour_ip_budget_across_accounts(quota_app):
    _, client, _, monkeypatch = quota_app
    routes_api = importlib.import_module("hackabull.routes_api")
    account = [0]
    monkeypatch.setattr(
        routes_api, "get_session_user",
        lambda request: {"google_id": f"reporter-{account[0]}", "email": "reporter@example.com"},
    )
    for index in range(10):
        account[0] = index
        assert client.post("/api/report", json={"url": "https://example.com", "reason": "invalid"}).status_code == 400
    account[0] = 10
    assert_limited(client.post("/api/report", json={"url": "https://example.com", "reason": "invalid"}))


def test_waitlist_has_address_and_ip_budgets(quota_app):
    app, client, db_path, _ = quota_app
    assert client.post("/waitlist", data={"email": "Person@Example.com"}).status_code == 200
    assert_html_limited(client.post("/waitlist", data={"email": "person@example.com"}))
    app.RATE_LIMITS.clear()
    for index in range(3):
        assert client.post("/waitlist", data={"email": f"person{index}@example.com"}).status_code == 200
    assert_html_limited(client.post("/waitlist", data={"email": "person4@example.com"}))
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM waitlist_signups").fetchone()[0] == 4


def test_go_ghost_budget_per_signed_in_user(quota_app):
    _, client, db_path, monkeypatch = quota_app
    import removals.engine as engine

    assert client.post("/auth/register", data={"email": "ghost@example.com", "password": "password123"}).status_code == 200
    monkeypatch.setattr(engine, "supported_broker", lambda name: type("Broker", (), {"optout_url": "https://example.com", "name": "Example"})())

    async def done(*args):
        return {"status": "submitted", "detail": "done", "targetUrl": "https://example.com"}

    monkeypatch.setattr(engine, "run_broker_removal", done)
    body = {"name": "Person", "email": "ghost@example.com"}
    for _ in range(3):
        assert client.post("/api/go-ghost/removals/example", json=body).status_code == 200
    assert_limited(client.post("/api/go-ghost/removals/example", json=body))
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT count(*) FROM go_ghost_removal_jobs").fetchone()[0] == 3


@pytest.mark.parametrize("path,data", [
    ("/auth/google", {"credential": "bad-token"}),
    ("/auth/verify", {"token": "bad-token"}),
])
def test_provider_login_has_five_per_minute_ip_budget(quota_app, path, data):
    _, client, _, monkeypatch = quota_app
    auth = importlib.import_module("hackabull.routes_scan_auth")

    def invalid(*args):
        raise ValueError("bad token")

    monkeypatch.setattr(auth.id_token, "verify_oauth2_token", invalid)
    for _ in range(5):
        response = client.post(path, json=data if path.endswith("verify") else None, data=data if path.endswith("google") else None)
        assert response.status_code == 401
    blocked = client.post(path, json=data if path.endswith("verify") else None, data=data if path.endswith("google") else None)
    if path.endswith("google"):
        assert_html_limited(blocked)
    else:
        assert_limited(blocked)
        assert blocked.headers["content-type"].startswith("application/json")


def test_provider_login_has_ten_per_fifteen_minutes_account_budget(quota_app):
    app, client, _, monkeypatch = quota_app
    auth = importlib.import_module("hackabull.routes_scan_auth")
    monkeypatch.setattr(auth, "LOCAL_AUTH_ENABLED", False)
    monkeypatch.setenv("RENDER", "true")
    for index in range(1, 11):
        response = google_login_for_quota(client, auth, monkeypatch,
                                          subject="same-google-sub", email="same@example.com", ip_index=index)
        assert response.status_code == 303
    assert_html_limited(google_login_for_quota(client, auth, monkeypatch,
                                               subject="same-google-sub", email="same@example.com", ip_index=11))


def test_mobile_login_shares_account_budget_with_web_login(quota_app):
    app, client, _, monkeypatch = quota_app
    auth = importlib.import_module("hackabull.routes_scan_auth")
    monkeypatch.setattr(auth, "LOCAL_AUTH_ENABLED", False)
    monkeypatch.setenv("RENDER", "true")
    for index in range(1, 6):
        response = google_login_for_quota(client, auth, monkeypatch,
                                          subject="shared-sub", email="shared@example.com", ip_index=index)
        assert response.status_code == 303
    monkeypatch.setattr(auth.id_token, "verify_oauth2_token", lambda *_: {
        "sub": "shared-sub", "email": "shared@example.com", "email_verified": True,
    })
    mobile = RawTestClient(app.qr_app, base_url="https://testserver")
    for index in range(6, 11):
        response = mobile.post("/auth/verify", json={"token": "valid"}, headers=edge_ip(index))
        assert response.status_code == 200
        assert "session" in response.json()
    blocked = mobile.post("/auth/verify", json={"token": "valid"}, headers=edge_ip(11))
    assert_limited(blocked)
    assert blocked.headers["content-type"].startswith("application/json")


def test_local_auth_presets_when_local_auth_is_enabled(quota_app):
    app, client, _, monkeypatch = quota_app
    for index in range(3):
        response = client.post("/auth/register", data={"email": f"not-an-email-{index}", "password": "password123"})
        assert response.status_code == 200
    assert_html_limited(client.post("/auth/register", data={"email": "not-an-email-3", "password": "password123"}))

    app.RATE_LIMITS.clear()
    monkeypatch.setenv("RENDER", "true")
    for index in range(1, 11):
        response = client.post("/auth/login", data={"email": "Someone@Example.com", "password": "wrong"}, headers=edge_ip(index))
        assert response.status_code == 200
    assert_html_limited(client.post("/auth/login", data={"email": "someone@example.com", "password": "wrong"}, headers=edge_ip(11)))
