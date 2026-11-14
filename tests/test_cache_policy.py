"""A saved verdict must not bypass live checks or enter shared HTML caches."""

import importlib
import sqlite3
import sys
from datetime import datetime

import pytest
from browser_client import BrowserTestClient as TestClient


@pytest.fixture()
def cache_app(tmp_path, monkeypatch):
    database = tmp_path / "cache.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.setenv("SAFESCAN_ML_ENABLED", "false")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)
    app = importlib.import_module("hackabull")
    app.init_db()
    qr_detect = importlib.import_module("hackabull.qr_detect")
    yield app, qr_detect, TestClient(app.qr_app, base_url="https://testserver"), database
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name in {"db", "storage"}:
            sys.modules.pop(name, None)


def _seed_verdict(database, url, status):
    with sqlite3.connect(database) as conn:
        conn.execute(
            "INSERT INTO scan_results (url, status, timestamp) VALUES (?, ?, ?)",
            (url, status, datetime.now().isoformat()),
        )


def _live_checks(qr_detect, monkeypatch, reputation_status):
    calls = []

    def reputation(url):
        calls.append(("reputation", url))
        return {"provider": "test", "status": reputation_status, "matches": [], "detail": "test result"}

    def redirects(url):
        calls.append(("redirects", url))
        return {"status": "OK", "count": 0, "final_url": url, "detail": "inspected"}

    monkeypatch.setattr(qr_detect, "check_url_reputation", reputation)
    monkeypatch.setattr(qr_detect, "inspect_redirects", redirects)
    return calls


@pytest.mark.parametrize("saved_status,live_status,expected_status", [
    ("SAFE", "MALICIOUS", "MALICIOUS"),
    ("MALICIOUS", "CLEAR", "SAFE"),
])
def test_saved_verdict_never_bypasses_live_checks(cache_app, monkeypatch, saved_status, live_status, expected_status):
    _, qr_detect, _, database = cache_app
    url = "https://plain.example/"
    _seed_verdict(database, url, saved_status)
    calls = _live_checks(qr_detect, monkeypatch, live_status)

    analysis = qr_detect.analyze_url_payload(url)

    assert [name for name, _ in calls] == ["reputation", "redirects"]
    assert analysis["source"] == "SafeScan Engine"
    assert analysis["status"] == expected_status


def test_incomplete_live_check_is_visible_even_with_saved_safe(cache_app, monkeypatch):
    _, qr_detect, _, database = cache_app
    url = "https://plain.example/"
    _seed_verdict(database, url, "SAFE")
    calls = _live_checks(qr_detect, monkeypatch, "ERROR")

    analysis = qr_detect.analyze_url_payload(url)

    assert [name for name, _ in calls] == ["reputation", "redirects"]
    assert analysis["source"] == "SafeScan Engine"
    assert any(reason["label"] == "Reputation lookup unavailable" for reason in analysis["reasons"])


def test_live_safe_result_is_not_written_to_verdict_cache(cache_app, monkeypatch):
    _, qr_detect, _, database = cache_app
    url = "https://new.example/"
    _live_checks(qr_detect, monkeypatch, "CLEAR")

    assert qr_detect.analyze_url_payload(url)["status"] == "SAFE"
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_results WHERE url = ?", (url,)).fetchone()[0] == 0


def test_dynamic_html_is_private_and_varies_by_cookie(cache_app):
    app, _, client, _ = cache_app

    guest = client.get("/")
    assert guest.status_code == 200
    assert guest.headers["Cache-Control"] == "private, no-store"
    assert "Cookie" in guest.headers["Vary"]

    cors = client.get("/", headers={"Origin": "https://testserver"})
    assert {part.strip() for part in cors.headers["Vary"].split(",")} >= {"Origin", "Cookie"}

    registered = client.post(
        "/auth/register", data={"email": "cache@example.com", "password": "password123"},
        follow_redirects=False,
    )
    assert registered.status_code in {200, 303}
    profile = client.get("/profile")
    assert profile.status_code == 200
    assert profile.headers["Cache-Control"] == "private, no-store"
    assert "Cookie" in profile.headers["Vary"]

    static_asset = client.get("/static/auth.js")
    assert static_asset.status_code == 200
    assert static_asset.headers["Cache-Control"].startswith("public,")
