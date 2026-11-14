"""Untrusted account and consent data must remain text in HTML pages."""

import importlib
import re
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def web_app(tmp_path, monkeypatch):
    database = tmp_path / "output.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.RATE_LIMITS.clear()
    client = TestClient(app.qr_app, base_url="https://testserver")
    yield app, client, database
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def _owner(client, database):
    assert client.post(
        "/auth/register", data={"email": "owner@example.com", "password": "password123"},
        follow_redirects=False,
    ).status_code == 303
    with sqlite3.connect(database) as conn:
        conn.execute("UPDATE users SET role = 'owner' WHERE email = 'owner@example.com'")


def test_historical_consent_fields_are_escaped_in_admin_table(web_app):
    _, client, database = web_app
    _owner(client, database)
    payload = '<img src=x onerror="alert(1)">'
    with sqlite3.connect(database) as conn:
        conn.execute(
            """INSERT INTO consent_logs
               (id, user_id, ip_hash, consent_given, consent_type, banner_version,
                timestamp, user_agent, locale, expiry_date)
               VALUES ('bad', ?, 'abc123', 1, ?, 'consent-v1', '2026-01-01', '', ?, '2027-01-01')""",
            (payload, payload, payload),
        )

    page = client.get("/legal/consent-log")

    assert page.status_code == 200
    assert payload not in page.text
    assert "&lt;img src=x onerror=" in page.text


def test_account_settings_email_cannot_break_out_of_attribute(web_app, monkeypatch):
    app, client, _ = web_app
    account = importlib.import_module("hackabull.routes_account")
    malicious = '\" autofocus onfocus=\"alert(1)'
    monkeypatch.setattr(account, "require_user", lambda request: {"email": malicious})

    page = client.get("/account/settings")

    assert page.status_code == 200
    assert malicious not in page.text
    assert "&#34; autofocus onfocus=&#34;alert(1)" in page.text


def test_payment_success_escapes_account_email(web_app, monkeypatch):
    _, client, _ = web_app
    pages = importlib.import_module("hackabull.routes_pages")
    malicious = '<img src=x onerror="alert(1)">'
    monkeypatch.setattr(pages, "record_alpha_subscription_purchase", lambda request: {
        "email": malicious, "purchased_at": "2026-01-01T00:00:00Z",
    })

    page = client.get("/pay/alpha/success")

    assert page.status_code == 200
    assert malicious not in page.text
    assert "&lt;img src=x onerror=" in page.text


def test_breach_report_escapes_submitted_text(web_app):
    _, client, database = web_app
    _owner(client, database)
    malicious = '</pre><img src=x onerror="alert(1)">'

    page = client.post("/admin/report-breach", data={
        "discovery_date": "2026-01-01T00:00:00Z", "data_categories": malicious,
        "users_affected": "1", "likely_consequences": "test", "measures_taken": "test",
    })

    assert page.status_code == 200
    assert malicious not in page.text
    assert "&lt;/pre&gt;&lt;img src=x onerror=" in page.text


def test_consent_payload_rejects_forged_user_and_invalid_fields(web_app):
    _, client, database = web_app
    for payload in (
        {"consentType": "all", "bannerVersion": "consent-v1", "userId": "victim"},
        {"consentType": "unknown", "bannerVersion": "consent-v1"},
        {"consentType": ["all"], "bannerVersion": "consent-v1"},
        {"consentType": {"value": "all"}, "bannerVersion": "consent-v1"},
        {"consentType": "all", "bannerVersion": "x" * 1000},
    ):
        assert client.post("/api/consent", json=payload).status_code == 400
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM consent_logs").fetchone()[0] == 0


def test_consent_uses_session_identity_and_caps_header_fields(web_app):
    _, client, database = web_app
    _owner(client, database)
    user_id = sqlite3.connect(database).execute(
        "SELECT google_id FROM users WHERE email = 'owner@example.com'"
    ).fetchone()[0]

    response = client.post(
        "/api/consent", json={"consentType": "all", "bannerVersion": "consent-v1"},
        headers={"Accept-Language": "x" * 2000, "User-Agent": "y" * 2000},
    )

    assert response.status_code == 200
    with sqlite3.connect(database) as conn:
        row = conn.execute("SELECT user_id, locale, user_agent FROM consent_logs").fetchone()
    assert row[0] == user_id
    assert len(row[1]) <= 35
    assert len(row[2]) <= 256


def test_no_template_marks_arbitrary_body_html_safe():
    templates = Path(__file__).resolve().parents[1] / "templates"
    unsafe = [str(file) for file in templates.rglob("*.html")
              if re.search(r"\|\s*safe\b", file.read_text())]
    assert unsafe == []
