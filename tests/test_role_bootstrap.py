"""Owner bootstrap must target a proven provider subject, never an email alone."""

import sqlite3

import pytest

from hackabull.cli import grant_owner, main


def _database(tmp_path):
    path = tmp_path / "bootstrap.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE users (google_id TEXT PRIMARY KEY, email TEXT, role TEXT, status TEXT)")
        conn.execute("""CREATE TABLE user_identities (
            provider TEXT, issuer TEXT, subject TEXT, user_id TEXT,
            email_at_link TEXT, email_verified INTEGER
        )""")
        conn.execute("""CREATE TABLE audit_logs (
            id TEXT PRIMARY KEY, actor_user_id TEXT, action TEXT, target_type TEXT,
            target_id TEXT, metadata TEXT, ip_address TEXT, user_agent TEXT, created_at TEXT
        )""")
        conn.executemany("INSERT INTO users VALUES (?, ?, 'user', 'active')", [
            ("first", "shared@example.com"), ("second", "shared@example.com")
        ])
        conn.execute("""INSERT INTO user_identities VALUES
            ('google', 'https://accounts.google.com', 'verified-sub', 'first',
             'shared@example.com', 1)""")
    return path


def test_owner_bootstrap_uses_exact_verified_google_subject(tmp_path):
    path = _database(tmp_path)

    assert grant_owner(path, "verified-sub", "shared@example.com") == "first"

    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT google_id, role FROM users ORDER BY google_id").fetchall() == [
            ("first", "owner"), ("second", "user")
        ]
        assert conn.execute("SELECT action, target_id FROM audit_logs").fetchall() == [
            ("admin.owner_bootstrapped", "first")
        ]


@pytest.mark.parametrize("subject,email", [
    ("other-sub", "shared@example.com"),
    ("verified-sub", "other@example.com"),
])
def test_owner_bootstrap_rejects_unproven_identity(tmp_path, subject, email):
    path = _database(tmp_path)

    with pytest.raises(ValueError):
        grant_owner(path, subject, email)

    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT role FROM users WHERE google_id = 'first'").fetchone()[0] == "user"
        assert conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0] == 0


def test_owner_bootstrap_requires_explicit_apply(tmp_path):
    path = _database(tmp_path)
    assert main([
        "grant-owner", "--database", str(path), "--google-sub", "verified-sub",
        "--expected-email", "shared@example.com",
    ]) == 2
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT role FROM users WHERE google_id = 'first'").fetchone()[0] == "user"


def test_owner_bootstrap_never_creates_a_missing_database(tmp_path):
    missing = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        grant_owner(missing, "verified-sub", "shared@example.com")
    assert not missing.exists()
