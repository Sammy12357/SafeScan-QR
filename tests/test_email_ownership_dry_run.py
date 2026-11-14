"""The email ownership inventory must never guess or change an account owner."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.security.email_ownership_dry_run import _mixed_owner, analyze_database, canonical_email


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "security" / "email_ownership_dry_run.py"


@pytest.fixture()
def collision_db(tmp_path):
    path = tmp_path / "collision.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE users (google_id TEXT PRIMARY KEY, email TEXT, role TEXT, status TEXT);
            CREATE TABLE user_identities (issuer TEXT, subject TEXT, user_id TEXT, email_at_link TEXT);
            CREATE TABLE scan_history (id TEXT PRIMARY KEY, email TEXT, user_id TEXT, url TEXT);
            CREATE TABLE scans (email TEXT PRIMARY KEY, user_id TEXT, wallet_address TEXT);
            CREATE TABLE scan_events (email TEXT, payload_hash TEXT, user_id TEXT);
            CREATE TABLE wallets (id TEXT PRIMARY KEY, user_id TEXT, address TEXT,
                                  verified INTEGER, disconnected_at TEXT);
            CREATE TABLE alpha_subscriptions (id TEXT PRIMARY KEY, user_id TEXT, email TEXT, status TEXT);
            CREATE TABLE local_credentials (email TEXT PRIMARY KEY, user_id TEXT, password_hash TEXT);
            CREATE TABLE waitlist_signups (email TEXT PRIMARY KEY);
            CREATE TABLE sessions (id TEXT PRIMARY KEY, google_id TEXT);
            CREATE TABLE referrals (id TEXT PRIMARY KEY, referrer_email TEXT, referred_email TEXT);
            CREATE TABLE audit_logs (id TEXT PRIMARY KEY, actor_user_id TEXT,
                                     target_type TEXT, target_id TEXT);
            """
        )
        conn.executemany(
            "INSERT INTO users VALUES (?, ?, ?, 'active')",
            [
                ("g1", "Alice@bücher.example", "owner"),
                ("auth0|g1", "Ａｌｉｃｅ@xn--bcher-kva.example", "user"),
                ("p1", "paid@example.com", "user"),
                ("p2", "PAID@EXAMPLE.COM", "user"),
                ("solo", "solo@example.com", "user"),
            ],
        )
        conn.executemany(
            "INSERT INTO user_identities VALUES (?, ?, ?, ?)",
            [
                ("https://accounts.google.com", "g1", "g1", "Alice@bücher.example"),
                ("https://tenant.example.auth0.com/", "google-oauth2|g1", "auth0|g1",
                 "Ａｌｉｃｅ@xn--bcher-kva.example"),
                ("https://tenant.example.auth0.com/", "github|orphan", "missing", "nobody@example.com"),
            ],
        )
        conn.executemany(
            "INSERT INTO scan_history VALUES (?, ?, ?, ?)",
            [
                ("ambiguous", "alice@bücher.example", "g1", "https://secret-qr-url.example/"),
                ("orphan-email", "lost@example.com", None, "https://secret-qr-url.example/"),
                ("orphan-id", "solo@example.com", "missing", "https://secret-qr-url.example/"),
                ("unbound", "solo@example.com", None, "https://secret-qr-url.example/"),
            ],
        )
        conn.executemany(
            "INSERT INTO scans VALUES (?, ?, ?)",
            [("Alice@bücher.example", "g1", "wallet-one"),
             ("Ａｌｉｃｅ@xn--bcher-kva.example", "auth0|g1", "wallet-two")],
        )
        conn.execute("INSERT INTO scan_events VALUES (?, ?, ?)", ("paid@example.com", "payload-secret", "g1"))
        conn.executemany(
            "INSERT INTO wallets VALUES (?, ?, ?, 1, NULL)",
            [("w1", "Alice@bücher.example", "wallet-one"),
             ("w2", "Ａｌｉｃｅ@xn--bcher-kva.example", "wallet-two")],
        )
        conn.execute("INSERT INTO alpha_subscriptions VALUES (?, ?, ?, 'active')",
                     ("paid", "p1", "paid@example.com"))
        conn.execute("INSERT INTO local_credentials VALUES (?, ?, ?)",
                     ("solo@example.com", "missing", "sentinel-password-hash"))
        conn.execute("INSERT INTO waitlist_signups VALUES (?)", ("guest@example.com",))
        conn.execute("INSERT INTO sessions VALUES (?, ?)", ("session", "missing"))
        conn.execute("INSERT INTO referrals VALUES (?, ?, ?)",
                     ("ref", "Alice@bücher.example", "guest@example.com"))
        conn.executemany("INSERT INTO audit_logs VALUES (?, ?, ?, ?)",
                         [("user-target", "g1", "user", "Alice@bücher.example"),
                          ("wallet-target", "g1", "wallet", "wallet-one")])
    return path


def test_canonical_key_handles_nfkc_casefold_and_idna_without_alias_guessing():
    assert canonical_email("Ａｌｉｃｅ@bücher.example") == "alice@xn--bcher-kva.example"
    assert canonical_email("alice@xn--bcher-kva.example") == "alice@xn--bcher-kva.example"
    assert canonical_email("Straße@EXAMPLE.com") == "strasse@example.com"
    assert canonical_email("a.b+tag@example.com") != canonical_email("ab@example.com")
    assert canonical_email('"a@b"@example.com') is None
    assert canonical_email("bad domain@example .com") is None


def test_mixed_owner_prefers_exact_account_id_even_when_it_looks_like_email():
    users = {"local@example.com": {"email": "local@example.com"}, "other": {"email": "LOCAL@example.com"}}
    email_users = {"local@example.com": {"local@example.com", "other"}}
    assert _mixed_owner("local@example.com", users, email_users) == ("stable_user_id", {"local@example.com"})
    assert _mixed_owner("LOCAL@example.com", users, email_users)[0] == "ambiguous_legacy_email"


def test_collision_audit_preserves_identity_namespaces_and_finds_ownership_risks(collision_db):
    before = hashlib.sha256(collision_db.read_bytes()).hexdigest()
    report = analyze_database(collision_db)
    assert hashlib.sha256(collision_db.read_bytes()).hexdigest() == before
    assert report["database_sha256"] == before

    summary = report["summary"]
    assert summary["users"] == 5
    assert summary["canonical_collision_groups"] == 2
    assert summary["canonical_collision_users"] == 4
    assert summary["privileged_collision_groups"] == 1
    assert summary["paid_collision_groups"] == 1
    assert summary["wallet_collision_groups"] == 1
    assert summary["multiple_wallet_collision_groups"] == 1
    assert summary["ambiguous_scan_rows"] == 4
    assert summary["email_user_id_mismatches"] == 1
    assert summary["orphaned_identity_links"] == 1
    assert summary["orphaned_user_id_references"] >= 3
    assert summary["orphaned_email_references"] >= 1
    assert summary["unbound_scan_rows"] == 2
    assert any(row["table"] == "referrals" and "ambiguous_email_reference" in row["issues"]
               for row in report["review"] if row["kind"] == "association")

    group = next(row for row in report["collisions"] if row["canonical_email"] == "alice@xn--bcher-kva.example")
    assert {row["user_id"] for row in group["users"]} == {"g1", "auth0|g1"}
    subjects = {identity["subject"] for user in group["users"] for identity in user["identities"]}
    assert subjects == {"g1", "google-oauth2|g1"}
    assert all("address" not in user for user in group["users"])

    private_text = json.dumps(report)
    assert "sentinel-password-hash" not in private_text
    assert "secret-qr-url" not in private_text
    assert "wallet-one" not in private_text
    assert "payload-secret" not in private_text
    assert "guest@example.com" not in private_text  # Unmatched public submissions are expected.


def test_cli_prints_counts_only_and_exclusive_private_report(collision_db, tmp_path):
    before = hashlib.sha256(collision_db.read_bytes()).hexdigest()
    private = tmp_path / "review.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--database", str(collision_db), "--private-report", str(private)],
        capture_output=True, text=True, check=True,
    )
    public = json.loads(result.stdout)
    assert set(public) == {"summary"}
    assert "Alice" not in result.stdout
    assert "g1" not in result.stdout
    assert "wallet-one" not in result.stdout
    assert "alice@xn--bcher-kva.example" in private.read_text()
    assert os.stat(private).st_mode & 0o777 == 0o600
    assert hashlib.sha256(collision_db.read_bytes()).hexdigest() == before
    private_before = hashlib.sha256(private.read_bytes()).hexdigest()

    repeat = subprocess.run(
        [sys.executable, str(SCRIPT), "--database", str(collision_db), "--private-report", str(private)],
        capture_output=True, text=True,
    )
    assert repeat.returncode == 1
    assert hashlib.sha256(private.read_bytes()).hexdigest() == private_before


def test_rejects_live_database_path_symlink_and_sqlite_sidecars(collision_db, tmp_path, monkeypatch):
    monkeypatch.setenv("SQLITE_DB_PATH", str(collision_db))
    with pytest.raises(ValueError, match="configured application database"):
        analyze_database(collision_db)
    monkeypatch.delenv("SQLITE_DB_PATH")

    link = tmp_path / "linked.db"
    link.symlink_to(collision_db)
    with pytest.raises(ValueError, match="Symlinked"):
        analyze_database(link)

    sidecar = Path(str(collision_db) + "-wal")
    sidecar.write_bytes(b"not a standalone backup")
    with pytest.raises(ValueError, match="sidecars"):
        analyze_database(collision_db)


def test_invalid_account_id_is_counted_without_losing_other_users(tmp_path):
    path = tmp_path / "malformed.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE users (google_id TEXT PRIMARY KEY, email TEXT)")
        conn.executemany("INSERT INTO users VALUES (?, ?)",
                         [(None, "nobody@example.com"), ("valid", "valid@example.com")])
    report = analyze_database(path)
    assert report["summary"]["users"] == 2
    assert report["summary"]["invalid_user_ids"] == 1
    assert report["summary"]["canonical_collision_groups"] == 0
    assert {item["kind"] for item in report["review"]} == {"invalid_user_id"}


def test_mixed_owner_columns_prefer_stable_ids_and_find_legacy_orphans(tmp_path):
    path = tmp_path / "mixed.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE users (google_id TEXT PRIMARY KEY, email TEXT, role TEXT, status TEXT);
            CREATE TABLE wallets (user_id TEXT, address TEXT, verified INTEGER, disconnected_at TEXT);
            CREATE TABLE wallet_nonces (user_id TEXT);
            CREATE TABLE ip_registry (user_id TEXT);
            CREATE TABLE fraud_flags (user_id TEXT, reviewed_by TEXT);
            CREATE TABLE scan_velocity (user_id TEXT);
            CREATE TABLE device_fingerprints (user_id TEXT);
            CREATE TABLE api_keys (created_by TEXT);
            CREATE TABLE url_blocklist (added_by TEXT);
            CREATE TABLE url_reports (reporter_email TEXT, reviewed_by TEXT);
            CREATE TABLE audit_logs (actor_user_id TEXT, target_type TEXT, target_id TEXT);
            """
        )
        conn.executemany("INSERT INTO users VALUES (?, ?, 'user', 'active')",
                         [("stable-1", "Case@example.com"), ("stable-2", "CASE@EXAMPLE.COM"),
                          ("unique", "unique@example.com")])
        conn.execute("INSERT INTO wallets VALUES ('stable-1', 'wallet-secret', 1, NULL)")
        conn.execute("INSERT INTO wallet_nonces VALUES ('stable-2')")
        conn.executemany("INSERT INTO ip_registry VALUES (?)",
                         [("stable-1",), ("case@example.com",), ("missing-id",), ("bad@",)])
        conn.executemany("INSERT INTO fraud_flags VALUES (?, ?)",
                         [("stable-1", "stable-2"), ("CASE@example.com", None)])
        conn.execute("INSERT INTO scan_velocity VALUES ('stable-1')")
        conn.executemany("INSERT INTO device_fingerprints VALUES (?)",
                         [("stable-2",), ("unique@example.com",)])
        conn.execute("INSERT INTO api_keys VALUES ('stable-1')")
        conn.execute("INSERT INTO url_blocklist VALUES ('stable-2')")
        conn.execute("INSERT INTO url_reports VALUES ('guest@example.com', 'stable-1')")
        conn.execute("INSERT INTO audit_logs VALUES ('stable-1', 'user', 'stable-2')")
        conn.execute("INSERT INTO audit_logs VALUES ('stable-1', 'wallet', 'wallet-secret')")

    report = analyze_database(path)
    summary = report["summary"]
    assert summary["wallet_collision_groups"] == 1  # Stable-ID wallet is attached to a collision group.
    assert summary["stable_user_id_references"] == 11
    assert summary["unique_legacy_email_references"] == 1
    assert summary["ambiguous_email_references"] == 2
    assert summary["orphaned_user_id_references"] == 1
    assert summary["invalid_mixed_owner_references"] == 1
    assert summary["invalid_email_references"] == 0
    assert summary["orphaned_email_references"] == 0
    assert summary["association_rows_requiring_review"] == 5
    assert any("legacy_email_owner_reference" in row["issues"] for row in report["review"])
    assert "wallet-secret" not in json.dumps(report)
    assert "guest@example.com" not in json.dumps(report)
    assert not any("stable-1" == row.get("mixed_references", {}).get("user_id")
                   for row in report["review"])
