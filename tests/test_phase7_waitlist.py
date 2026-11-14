"""Unverified email submissions must not enter the deliverable waitlist."""

import hashlib
import importlib
import re
import sqlite3
import sys

import pytest
from fastapi.testclient import TestClient

from browser_client import BrowserTestClient


@pytest.fixture()
def waitlist_app(tmp_path, monkeypatch):
    db_path = tmp_path / "waitlist.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    pages = importlib.import_module("hackabull.routes_pages")
    app.RATE_LIMITS.clear()
    sent = []
    monkeypatch.setattr(pages, "email_sending_configured", lambda: True)

    def capture_email(*args):
        sent.append(args)
        return True

    monkeypatch.setattr(pages, "send_email", capture_email)
    yield app, BrowserTestClient(app.qr_app, base_url="https://testserver"), db_path, sent, pages
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def _token_from_email(sent):
    assert len(sent) == 1
    match = re.search(r"https://testserver/waitlist/confirm\?token=([A-Za-z0-9_-]{43})", sent[0][2])
    assert match
    return match.group(1)


def _rows(db_path, sql):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(sql).fetchall()


def test_confirmation_is_one_time_and_only_it_adds_a_signup(waitlist_app):
    app, browser, db_path, sent, _ = waitlist_app
    submitted = browser.post("/waitlist", data={"email": " Person@Example.com "})
    assert submitted.status_code == 200
    assert "check its inbox" in submitted.text
    assert _rows(db_path, "SELECT count(*) FROM waitlist_signups") == [(0,)]
    token = _token_from_email(sent)
    stored = _rows(db_path, "SELECT email, token_hash FROM waitlist_confirmation_tokens")
    assert stored == [("person@example.com", hashlib.sha256(token.encode()).hexdigest())]
    assert token not in db_path.read_bytes().decode("latin-1")

    start = browser.get(f"/waitlist/confirm?token={token}", follow_redirects=False)
    assert start.status_code == 303
    assert start.headers["location"] == "/waitlist/confirm"
    assert start.headers["referrer-policy"] == "no-referrer"
    page = browser.get("/waitlist/confirm")
    assert page.status_code == 200
    assert "Confirm my email" in page.text
    assert token not in page.text

    confirmed = browser.post("/waitlist/confirm")
    assert confirmed.status_code == 200
    assert "email is confirmed" in confirmed.text
    assert _rows(db_path, "SELECT email, confirmed_at IS NOT NULL FROM waitlist_signups") == [("person@example.com", 1)]
    assert _rows(db_path, "SELECT count(*) FROM waitlist_confirmation_tokens") == [(0,)]
    assert browser.cookies.get("__Host-safescan_waitlist_confirm") is None

    replay = browser.get(f"/waitlist/confirm?token={token}", follow_redirects=False)
    assert replay.status_code == 303
    assert browser.post("/waitlist/confirm").status_code == 400
    assert _rows(db_path, "SELECT count(*) FROM waitlist_signups") == [(1,)]

    app.RATE_LIMITS.clear()
    assert browser.post("/waitlist", data={"email": "person@example.com"}).status_code == 200
    assert len(sent) == 1


def test_missing_smtp_or_send_failure_never_adds_pending_or_confirmed(waitlist_app, monkeypatch):
    app, browser, db_path, sent, pages = waitlist_app
    monkeypatch.setattr(pages, "email_sending_configured", lambda: False)
    unavailable = browser.post("/waitlist", data={"email": "person@example.com"})
    assert unavailable.status_code == 503
    assert "your address was not added" in unavailable.text
    assert _rows(db_path, "SELECT count(*) FROM waitlist_confirmation_tokens") == [(0,)]

    monkeypatch.setattr(pages, "email_sending_configured", lambda: True)
    monkeypatch.setattr(pages, "send_email", lambda *_: False)
    app.RATE_LIMITS.clear()
    failed = browser.post("/waitlist", data={"email": "person@example.com"})
    assert failed.status_code == 503
    assert _rows(db_path, "SELECT count(*) FROM waitlist_confirmation_tokens") == [(0,)]
    assert _rows(db_path, "SELECT count(*) FROM waitlist_signups") == [(0,)]
    assert sent == []


def test_expired_token_and_missing_browser_csrf_do_not_confirm(waitlist_app):
    app, browser, db_path, sent, _ = waitlist_app
    assert browser.post("/waitlist", data={"email": "person@example.com"}).status_code == 200
    token = _token_from_email(sent)
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE waitlist_confirmation_tokens SET expires_at = '2000-01-01T00:00:00+00:00'")
    assert browser.get(f"/waitlist/confirm?token={token}", follow_redirects=False).status_code == 303
    raw = TestClient(app.qr_app, base_url="https://testserver")
    raw.cookies.update(browser.cookies)
    assert raw.post("/waitlist/confirm").status_code == 403
    expired = browser.post("/waitlist/confirm")
    assert expired.status_code == 400
    assert _rows(db_path, "SELECT count(*) FROM waitlist_signups") == [(0,)]


def test_old_waitlist_rows_remain_unconfirmed_after_schema_upgrade(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE waitlist_signups (email TEXT PRIMARY KEY, source TEXT, created_at TEXT NOT NULL)")
        conn.execute("INSERT INTO waitlist_signups VALUES ('legacy@example.com', 'footer', '2026-01-01')")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    importlib.import_module("hackabull")
    admin_data = importlib.import_module("hackabull.admin_data")
    assert _rows(db_path, "SELECT email, confirmed_at FROM waitlist_signups") == [("legacy@example.com", None)]
    assert all(row["email"] != "legacy@example.com" for row in admin_data.fetch_waitlist()["rows"])
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
