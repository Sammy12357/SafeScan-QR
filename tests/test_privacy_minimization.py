"""Private URL queries are useful during analysis but not in persisted scans."""

from __future__ import annotations

import importlib
import json
import sqlite3
import sys
from datetime import datetime, timezone

import pytest


@pytest.fixture()
def privacy_app(tmp_path, monkeypatch):
    db_path = tmp_path / "privacy.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("QR_PAYLOAD_FINGERPRINT_KEY", "test-only-key-that-is-at-least-thirty-two-bytes")
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)
    importlib.import_module("hackabull")
    yield db_path
    for name in list(sys.modules):
        if name == "hackabull" or name.startswith("hackabull.") or name == "db":
            sys.modules.pop(name, None)


def query(db_path, statement, params=()):
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(statement, params)]


def test_web_scan_storage_strips_query_but_keeps_host_and_path(privacy_app):
    history = importlib.import_module("hackabull.history")
    referrals = importlib.import_module("hackabull.referrals")
    raw = "https://example.com/pay?code=SECRET123#private"
    analysis = {
        "score": 20, "status": "SAFE", "reasons": [
            {"label": "Redirect https://example.com/pay?code=SECRET123", "severity": "low", "detail": raw}
        ],
    }
    history.save_scan_history("person@example.com", raw, analysis)
    assert referrals.record_unique_scan("person@example.com", raw, "") is True
    rows = query(privacy_app, "SELECT url, signals FROM scan_history")
    assert rows[0]["url"] == "https://example.com/pay"
    assert "SECRET123" not in rows[0]["signals"]
    assert query(privacy_app, "SELECT url_found FROM scan_events")[0]["url_found"] == "https://example.com/pay"
    assert "SECRET123" not in query(privacy_app, "SELECT url_found FROM scans")[0]["url_found"]


def test_result_cache_uses_keyed_index_and_preserves_exact_lookup(privacy_app):
    helpers = importlib.import_module("hackabull.request_helpers")
    raw = "https://example.com/pay?code=SECRET123"
    helpers.save_to_cache(raw, "CAUTION")
    assert helpers.get_cached_result(raw) == "CAUTION"
    assert helpers.get_cached_result("https://example.com/pay?code=other") is None
    key = query(privacy_app, "SELECT url FROM scan_results")[0]["url"]
    assert key.startswith("hmac:")
    assert "SECRET123" not in key


def test_legacy_scan_rows_are_scrubbed_without_erasing_count(privacy_app):
    retention = importlib.import_module("hackabull.privacy_retention")
    raw = "https://example.com/pay?code=OLDSECRET#fragment"
    with sqlite3.connect(privacy_app) as conn:
        conn.execute("INSERT INTO scan_history (id,email,url,risk_score,verdict,signals,created_at) VALUES (?,?,?,?,?,?,?)", (
            "old", "person@example.com", raw, 20, "SAFE",
            json.dumps([{"label": raw, "detail": raw}]), "2026-10-01T00:00:00Z",
        ))
        conn.execute("INSERT INTO scans (email,url_found,scan_count) VALUES (?,?,?)", ("person@example.com", raw, 7))
        conn.execute("INSERT INTO scan_events (email,payload_hash,url_found,first_scanned_at) VALUES (?,?,?,?)", (
            "person@example.com", "legacy-unkeyed-hash", raw, "2026-10-01T00:00:00Z",
        ))
        conn.execute("INSERT INTO scan_velocity (user_id,last_scan_url,updated_at) VALUES (?,?,?)", (
            "person", raw, "2026-10-01T00:00:00Z",
        ))
    changed = retention.scrub_legacy_scan_storage()
    assert changed == {"scan_history": 1, "scan_events": 1, "scans": 1, "scan_velocity": 1}
    row = query(privacy_app, "SELECT url,signals FROM scan_history")[0]
    assert row["url"] == "https://example.com/pay"
    assert "OLDSECRET" not in row["signals"]
    assert query(privacy_app, "SELECT scan_count,url_found FROM scans") == [{"scan_count": 7, "url_found": ""}]
    assert query(privacy_app, "SELECT count(*) AS n FROM scan_events")[0]["n"] == 0
    assert query(privacy_app, "SELECT last_scan_url FROM scan_velocity")[0]["last_scan_url"] == "https://example.com/pay"
    assert retention.scrub_legacy_scan_storage() == {"scan_history": 0, "scan_events": 0, "scans": 0, "scan_velocity": 0}


def test_retention_obeys_published_five_year_period_and_legal_hold(privacy_app, monkeypatch):
    retention = importlib.import_module("hackabull.privacy_retention")
    now = datetime(2026, 11, 15, tzinfo=timezone.utc)
    with sqlite3.connect(privacy_app) as conn:
        for ident, stamp in (("old", "2021-11-14T00:00:00Z"), ("new", "2021-11-16T00:00:00Z")):
            conn.execute("INSERT INTO consent_logs (id,ip_hash,consent_given,consent_type,banner_version,timestamp) VALUES (?,?,?,?,?,?)", (
                ident, "hash", 0, "essential_only", "consent-v1", stamp,
            ))
        conn.execute("INSERT INTO scan_results VALUES (?,?,?)", ("hmac:old", "SAFE", "2026-11-13T00:00:00"))
        conn.execute("INSERT INTO scan_results VALUES (?,?,?)", ("hmac:new", "SAFE", "2026-11-15T00:00:00"))
    monkeypatch.setenv("RETENTION_LEGAL_HOLD", "true")
    assert retention.run_retention(now) == {"scan_results": 1, "consent_logs": 0}
    assert [row["id"] for row in query(privacy_app, "SELECT id FROM consent_logs ORDER BY id")] == ["new", "old"]
    monkeypatch.delenv("RETENTION_LEGAL_HOLD")
    assert retention.run_retention(now) == {"scan_results": 0, "consent_logs": 1}
    assert [row["id"] for row in query(privacy_app, "SELECT id FROM consent_logs ORDER BY id")] == ["new"]
