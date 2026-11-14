"""The identity inventory must be conservative and read-only."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.security.identity_dry_run import analyze_database


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "security" / "identity_dry_run.py"


@pytest.fixture()
def legacy_db(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE users (google_id TEXT PRIMARY KEY, email TEXT, google_sub TEXT,
                                role TEXT, status TEXT);
            CREATE TABLE local_credentials (email TEXT PRIMARY KEY, user_id TEXT, password_hash TEXT);
            CREATE TABLE sessions (google_id TEXT, revoked_at TEXT);
            CREATE TABLE persistent_sessions (user_id TEXT, revoked_at TEXT);
            CREATE TABLE audit_logs (actor_user_id TEXT, action TEXT, metadata TEXT);
            """
        )
        conn.executemany(
            "INSERT INTO users VALUES (?, ?, ?, ?, 'active')",
            [
                ("google-sub-1", "alpha@example.com", "google-sub-1", "user"),
                ("google-oauth2|X", "g-auth0@example.com", "google-oauth2|X", "user"),
                ("github|X", "h-auth0@example.com", "github|X", "user"),
                ("X", "legacy@example.com", "X", "user"),
                ("local_123", "victim@example.com", "other-sub", "owner"),
                ("other-sub", "Victim@example.com", "other-sub", "user"),
            ],
        )
        conn.execute("INSERT INTO local_credentials VALUES (?, ?, ?)",
                     ("victim@example.com", "local_123", "sentinel-password-hash"))
        conn.executemany(
            "INSERT INTO audit_logs VALUES (?, 'user.login', ?)",
            [
                ("google-sub-1", json.dumps({"provider": "google_mobile"})),
                ("X", json.dumps({"provider": "auth0_mobile"})),
            ],
        )
        conn.executemany("INSERT INTO sessions VALUES (?, NULL)", [("google-sub-1",), ("missing-user",)])
        conn.execute("INSERT INTO persistent_sessions VALUES (?, NULL)", ("local_123",))
    return path


def test_dry_run_preserves_provider_namespaces_and_flags_uncertain_links(legacy_db):
    before = hashlib.sha256(legacy_db.read_bytes()).digest()
    report = analyze_database(legacy_db, auth0_issuer="https://tenant.example.auth0.com/")
    assert hashlib.sha256(legacy_db.read_bytes()).digest() == before

    identities = {(row["provider"], row["issuer"], row["subject"]) for row in report["candidates"]}
    assert ("google", "https://accounts.google.com", "google-sub-1") in identities
    assert ("auth0", "https://tenant.example.auth0.com/", "google-oauth2|X") in identities
    assert ("auth0", "https://tenant.example.auth0.com/", "github|X") in identities
    assert len(identities) == len(report["candidates"])
    assert not any(row["subject"] == "X" for row in report["candidates"])
    assert not any(row["user_id"] == "local_123" for row in report["candidates"])

    reasons = {item["reason"] for item in report["review"]}
    assert {"auth0_subject_lost", "same_email_multiple_users", "local_credential_link",
            "google_sub_mismatch", "privileged_role", "orphaned_session"} <= reasons
    assert report["summary"]["users"] == 6
    assert report["summary"]["unrevoked_sessions"] == 3
    assert report["summary"]["orphaned_sessions"] == 1


def test_cli_stdout_is_aggregate_only_and_private_report_is_0600(legacy_db, tmp_path):
    before = hashlib.sha256(legacy_db.read_bytes()).digest()
    private_report = tmp_path / "identity-private.json"
    run = subprocess.run(
        [sys.executable, str(SCRIPT), "--database", str(legacy_db),
         "--auth0-issuer", "https://tenant.example.auth0.com/",
         "--private-report", str(private_report)],
        capture_output=True, text=True, check=True,
    )
    public = json.loads(run.stdout)
    assert "summary" in public
    assert "candidates" not in public
    assert "review" not in public
    assert "alpha@example.com" not in run.stdout
    assert "google-sub-1" not in run.stdout
    assert "victim@example.com" in private_report.read_text()
    assert "sentinel-password-hash" not in private_report.read_text()
    assert "sentinel-password-hash" not in run.stdout
    assert os.stat(private_report).st_mode & 0o777 == 0o600
    assert hashlib.sha256(legacy_db.read_bytes()).digest() == before

    repeated = subprocess.run(
        [sys.executable, str(SCRIPT), "--database", str(legacy_db),
         "--private-report", str(private_report)],
        capture_output=True, text=True,
    )
    assert repeated.returncode != 0, "never overwrite a prior sensitive report"


def test_missing_auth0_issuer_never_infers_auth0_identity(legacy_db):
    report = analyze_database(legacy_db)
    assert all(row["provider"] != "auth0" for row in report["candidates"])
    assert "auth0_issuer_required" in {item["reason"] for item in report["review"]}


def test_verified_email_and_stripped_subject_do_not_link_accounts(legacy_db):
    with sqlite3.connect(legacy_db) as conn:
        conn.execute("INSERT INTO audit_logs VALUES (?, 'user.login', ?)",
                     ("other-sub", json.dumps({"provider": "google_mobile"})))
        conn.execute("INSERT INTO local_credentials VALUES (?, ?, ?)",
                     ("orphan@example.com", "missing-local-user", "another-secret-hash"))
    report = analyze_database(legacy_db, auth0_issuer="https://tenant.example.auth0.com/")
    proposed_users = {row["user_id"] for row in report["candidates"]}
    assert "other-sub" not in proposed_users  # Its verified email collides with another account.
    assert "X" not in proposed_users  # Auth0's full issuer subject was discarded.
    assert "missing-local-user" not in proposed_users
    assert "orphaned_local_credential" in {item["reason"] for item in report["review"]}


def test_rejects_non_https_auth0_issuer(legacy_db):
    with pytest.raises(ValueError):
        analyze_database(legacy_db, auth0_issuer="http://tenant.example.auth0.com/")
