"""Owner-scoped privacy export, correction, and cautious account erasure."""

from __future__ import annotations

import importlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def rights_db(tmp_path, monkeypatch):
    path = tmp_path / "rights.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{path}")
    monkeypatch.setenv("APP_URL", "https://testserver")
    monkeypatch.setenv("MOCK_MODE", "true")
    monkeypatch.delenv("RETENTION_LEGAL_HOLD", raising=False)
    for name in tuple(sys.modules):
        if name == "db" or name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)
    legal = importlib.import_module("hackabull.legal")
    with sqlite3.connect(path) as conn:
        conn.executemany("INSERT INTO users (google_id, email, display_name) VALUES (?, ?, ?)", (
            ("a", "a@example.com", "Old Name"), ("b", "b@example.com", "Other Name"),
        ))
    yield legal, path
    for name in tuple(sys.modules):
        if name == "db" or name == "hackabull" or name.startswith("hackabull."):
            sys.modules.pop(name, None)


def rows(path, sql, params=()):
    with sqlite3.connect(path) as conn:
        return conn.execute(sql, params).fetchall()


def snapshot(path):
    """Compare all application rows, not just the table that raised review."""
    with sqlite3.connect(path) as conn:
        tables = [row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )]
        return {table: conn.execute(f'SELECT * FROM "{table}"').fetchall() for table in tables}


def seed_erasure_rows(conn):
    conn.execute("INSERT INTO scan_history (id,email,url,created_at,user_id) VALUES (?,?,?,?,?)",
                 ("scan", "a@example.com", "https://example.com", "now", "a"))
    conn.execute("INSERT INTO go_ghost_removal_jobs (id,user_id,email,broker,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                 ("ghost", "a", "a@example.com", "broker", "pending", "now", "now"))
    conn.execute("INSERT INTO sessions (id,google_id,created_at,expires_at,last_active) VALUES (?,?,?,?,?)",
                 ("session", "a", "now", "later", "now"))


def test_export_includes_owner_records_but_withholds_credentials_and_third_party_details(rights_db):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO wallets (id,user_id,address,connected_at) VALUES (?,?,?,?)", ("wa", "a", "wallet-a", "2026-11-15"))
        conn.execute("INSERT INTO wallets (id,user_id,address,connected_at) VALUES (?,?,?,?)", ("wb", "b", "wallet-b", "2026-11-15"))
        conn.execute("INSERT INTO sessions (id,google_id,created_at,expires_at,last_active) VALUES (?,?,?,?,?)", ("SECRET_SESSION", "a", "now", "later", "now"))
        conn.execute("INSERT INTO local_credentials (email,password_hash,created_at,user_id) VALUES (?,?,?,?)", ("a@example.com", "SECRET_PASSWORD_HASH", "now", "a"))
        conn.execute("INSERT INTO referrals (id,referrer_email,referred_email,created_at) VALUES (?,?,?,?)", ("ref", "a@example.com", "third-party@example.com", "now"))
        conn.execute("INSERT INTO audit_logs (id,actor_user_id,action,metadata,created_at) VALUES (?,?,?,?,?)", ("log", "a", "user.login", "SECRET_AUDIT_DETAIL", "now"))
        conn.execute("""INSERT INTO api_keys (id,name,key_hint,key_hash,scopes,created_by,created_at)
            VALUES (?,?,?,?,?,?,?)""", ("key", "test key", "hint", "SECRET_API_KEY_HASH", "[]", "a@example.com", "now"))
    export = legal.get_user_export("a@example.com", "a")
    serialized = json.dumps(export)
    assert export["account"][0]["display_name"] == "Old Name"
    assert export["wallets"][0]["address"] == "wallet-a"
    assert len(export["sessions"]) == 1
    assert "auditLogs" in export["manualReview"]
    assert "records matched by email require ownership review" in export["manualReview"]
    for secret in ("SECRET_SESSION", "SECRET_PASSWORD_HASH", "SECRET_AUDIT_DETAIL", "SECRET_API_KEY_HASH", "third-party@example.com", "wallet-b"):
        assert secret not in serialized


def test_email_only_records_cannot_be_exported_or_erased_by_account_email_match(rights_db):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        conn.execute("""INSERT INTO data_requests
            (id,email,request_type,details,status,submitted_at)
            VALUES (?,?,?,?,?,?)""", (
            "unverified-request", "a@example.com", "access", "OTHER_PERSON_PRIVATE_DETAIL", "submitted", "now",
        ))
        conn.execute("""INSERT INTO scan_history
            (id,email,url,created_at,user_id) VALUES (?,?,?,?,?)""", (
            "unbound-scan", "a@example.com", "https://third-party.example/private", "now", None,
        ))
        conn.execute("INSERT INTO waitlist_signups (email,created_at) VALUES (?,?)", ("a@example.com", "now"))
    exported = legal.get_user_export("a@example.com", "a")
    serialized = json.dumps(exported)
    assert "OTHER_PERSON_PRIVATE_DETAIL" not in serialized
    assert "third-party.example" not in serialized
    assert exported["dataRequests"] == []
    assert exported["scanHistory"] == []
    assert "records matched by email require ownership review" in exported["manualReview"]
    before = snapshot(path)
    assert legal.delete_user_data("a@example.com", "a") is False
    assert snapshot(path) == before


def test_other_account_scan_with_same_email_requires_review(rights_db):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO scan_history (id,email,url,created_at,user_id) VALUES (?,?,?,?,?)", (
            "foreign-scan", "a@example.com", "https://foreign.example/private", "now", "b",
        ))
    exported = legal.get_user_export("a@example.com", "a")
    assert exported["scanHistory"] == []
    assert "records matched by email require ownership review" in exported["manualReview"]
    before = snapshot(path)
    assert legal.delete_user_data("a@example.com", "a") is False
    assert snapshot(path) == before


def test_billing_review_keeps_every_row_for_manual_decision(rights_db):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        seed_erasure_rows(conn)
        conn.execute("""INSERT INTO stripe_checkout_intents
            (session_id,user_id,email,price_id,product_id,amount_cents,currency,
             consent_version,consent_text,refund_text,accepted_at,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
            "checkout", "a", "a@example.com", "price", "product", 1000, "usd",
            "v1", "terms", "refund", "now", "now",
        ))
    before = snapshot(path)
    assert legal.delete_user_data("a@example.com", "a") is False
    assert snapshot(path) == before


@pytest.mark.parametrize("blocker_sql, blocker_params", [
    ("INSERT INTO consent_logs (id,user_id,ip_hash,consent_given,consent_type,banner_version,timestamp) VALUES (?,?,?,?,?,?,?)",
     ("consent", "a", "iphash", 1, "all", "v1", "now")),
    ("INSERT INTO audit_logs (id,actor_user_id,action,created_at) VALUES (?,?,?,?)",
     ("audit", "a", "user.login", "now")),
    ("INSERT INTO upload_artifacts (id,user_id,object_key,backend,byte_size,sha256,created_at) VALUES (?,?,?,?,?,?,?)",
     ("upload", "a", "object", "local", 1, "digest", "now")),
    ("INSERT INTO fraud_flags (id,user_id,check_name,severity,reason,created_at) VALUES (?,?,?,?,?,?)",
     ("fraud", "a", "check", "medium", "review", "now")),
], ids=["consent", "security-audit", "retained-upload", "fraud-evidence"])
def test_pending_review_never_partially_erases_scans_or_go_ghost(rights_db, blocker_sql, blocker_params):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        seed_erasure_rows(conn)
        conn.execute(blocker_sql, blocker_params)
    before = snapshot(path)
    assert legal.delete_user_data("a@example.com", "a") is False
    assert snapshot(path) == before


def test_ambiguous_ownership_never_partially_erases(rights_db):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        seed_erasure_rows(conn)
        conn.execute("INSERT INTO users (google_id,email) VALUES (?,?)", ("collision", "A@example.com"))
    before = snapshot(path)
    assert legal.delete_user_data("a@example.com", "a") is False
    assert snapshot(path) == before


def test_legal_hold_never_partially_erases(rights_db, monkeypatch):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        seed_erasure_rows(conn)
    before = snapshot(path)
    monkeypatch.setenv("RETENTION_LEGAL_HOLD", "true")
    assert legal.delete_user_data("a@example.com", "a") is False
    assert snapshot(path) == before


def test_clean_erasure_removes_bound_rows_and_credentials(rights_db):
    legal, path = rights_db
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO wallets (id,user_id,address,connected_at) VALUES (?,?,?,?)", ("wa", "a", "wallet-a", "now"))
        conn.execute("INSERT INTO local_credentials (email,password_hash,created_at,user_id) VALUES (?,?,?,?)", ("a@example.com", "hash", "now", "a"))
        conn.execute("INSERT INTO scan_history (id,email,url,created_at,user_id) VALUES (?,?,?,?,?)", ("scan", "a@example.com", "https://example.com", "now", "a"))
    assert legal.delete_user_data("a@example.com", "a") is True
    assert rows(path, "SELECT google_id FROM users") == [("b",)]
    for table in ("wallets", "local_credentials", "scan_history"):
        assert rows(path, f"SELECT * FROM {table}") == []


def test_display_name_correction_requires_unique_owner_and_valid_value(rights_db):
    legal, path = rights_db
    assert legal.correct_display_name("a@example.com", "b", "Stolen") is False
    assert legal.correct_display_name("a@example.com", "a", "\x00bad") is False
    assert legal.correct_display_name("a@example.com", "a", "New Name") is True
    assert rows(path, "SELECT display_name FROM users WHERE google_id = 'a'") == [("New Name",)]
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO users (google_id,email) VALUES (?,?)", ("collision", "A@example.com"))
    assert legal.correct_display_name("a@example.com", "a", "Other Name") is False


def test_http_correction_requires_signed_in_email_and_records_completion(rights_db):
    _, path = rights_db
    now = datetime.now(timezone.utc)
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO age_eligibility (user_id,minimum_age,confirmed_at) VALUES (?,?,?)", ("a", 16, now.isoformat()))
        conn.execute("""INSERT INTO sessions (id,google_id,created_at,expires_at,last_active)
            VALUES (?,?,?,?,?)""", ("test-session", "a", now.replace(tzinfo=None).isoformat(),
                                   (now + timedelta(hours=1)).replace(tzinfo=None).isoformat(), now.replace(tzinfo=None).isoformat()))
    app = importlib.import_module("hackabull").qr_app
    client = TestClient(app, base_url="https://testserver")
    headers = {"Authorization": "Bearer test-session"}
    denied = client.post("/legal/data-request", headers=headers, data={
        "email": "b@example.com", "request_type": "rectification",
        "correction_field": "display_name", "correction_value": "Taken",
    })
    assert denied.status_code == 200
    assert rows(path, "SELECT status FROM data_requests WHERE email = 'b@example.com'") == [("submitted",)]
    assert rows(path, "SELECT display_name FROM users WHERE google_id = 'b'") == [("Other Name",)]
    completed = client.post("/legal/data-request", headers=headers, data={
        "email": "a@example.com", "request_type": "rectification",
        "correction_field": "display_name", "correction_value": "  Corrected  ",
    })
    assert completed.status_code == 200
    assert rows(path, "SELECT status FROM data_requests WHERE email = 'a@example.com'") == [("completed",)]
    recorded = json.loads(rows(path, "SELECT details FROM data_requests WHERE email = 'a@example.com'")[0][0])
    assert recorded["requested_value"] == "Corrected"
    assert rows(path, "SELECT display_name FROM users WHERE google_id = 'a'") == [("Corrected",)]
    download = client.post("/legal/data-export", headers=headers)
    assert download.status_code == 200
    assert download.headers["Cache-Control"] == "no-store"
    assert download.headers["Content-Disposition"] == 'attachment; filename="safescan-data.json"'
    assert download.json()["account"][0]["display_name"] == "Corrected"
    assert client.post("/legal/data-export").status_code == 401
