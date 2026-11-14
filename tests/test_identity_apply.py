"""Approved mappings must be applied only to a new, private offline DB copy."""

import hashlib
import json
import os
import sqlite3

import pytest

from scripts.security.identity_apply import main, prepare_identity_copy


def _source(tmp_path):
    path = tmp_path / "backup.db"
    with sqlite3.connect(path) as conn:
        conn.execute("""CREATE TABLE users (
            google_id TEXT PRIMARY KEY, email TEXT, role TEXT, status TEXT,
            google_sub TEXT)""")
        conn.executemany("INSERT INTO users VALUES (?, ?, ?, 'active', ?)", [
            ("google-123", "person@example.com", "user", "google-123"),
            ("owner-456", "owner@example.com", "owner", "owner-456"),
            ("legacy-auth0", "mobile@example.com", "user", "legacy-auth0"),
        ])
    return path


def _approved(tmp_path, source, mappings):
    path = tmp_path / "approved.json"
    path.write_text(json.dumps({
        "format": "safescan-identity-mappings-v1",
        "database_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "mappings": mappings,
    }))
    os.chmod(path, 0o600)
    return path


def _google(subject="google-123", user_id="google-123", email="person@example.com"):
    return {
        "provider": "google", "issuer": "https://accounts.google.com",
        "subject": subject, "user_id": user_id, "email_at_link": email,
        "email_verified": True,
    }


def _auth0():
    return {
        "provider": "auth0", "issuer": "https://example.auth0.com/",
        "subject": "google-oauth2|full-sub", "user_id": "legacy-auth0",
        "email_at_link": "mobile@example.com", "email_verified": True,
    }


def test_applies_exact_mapping_to_new_private_copy_and_preserves_input(tmp_path):
    source = _source(tmp_path)
    original = source.read_bytes()
    approved = _approved(tmp_path, source, [_google(), _auth0()])
    output = tmp_path / "migrated.db"

    assert prepare_identity_copy(source, approved, output, auth0_issuer="https://example.auth0.com/") == 2

    assert source.read_bytes() == original
    assert os.stat(output).st_mode & 0o777 == 0o600
    with sqlite3.connect(output) as conn:
        assert conn.execute(
            "SELECT provider, issuer, subject, user_id FROM user_identities ORDER BY provider"
        ).fetchall() == [
            ("auth0", "https://example.auth0.com/", "google-oauth2|full-sub", "legacy-auth0"),
            ("google", "https://accounts.google.com", "google-123", "google-123"),
        ]


def test_rejects_unapproved_source_or_email_change_without_output(tmp_path):
    source = _source(tmp_path)
    approved = _approved(tmp_path, source, [_google(email="other@example.com")])
    output = tmp_path / "migrated.db"

    with pytest.raises(ValueError):
        prepare_identity_copy(source, approved, output)
    assert not output.exists()

    approved = _approved(tmp_path, source, [_google()])
    with sqlite3.connect(source) as conn:
        conn.execute("UPDATE users SET email='changed@example.com' WHERE google_id='google-123'")
    with pytest.raises(ValueError):
        prepare_identity_copy(source, approved, output)
    assert not output.exists()


def test_privileged_mapping_requires_separate_explicit_flag(tmp_path):
    source = _source(tmp_path)
    approved = _approved(tmp_path, source, [_google("owner-456", "owner-456", "owner@example.com")])
    output = tmp_path / "migrated.db"

    with pytest.raises(ValueError):
        prepare_identity_copy(source, approved, output)
    assert not output.exists()
    assert prepare_identity_copy(source, approved, output, allow_privileged=True) == 1


def test_conflicting_existing_mapping_rolls_back_and_removes_copy(tmp_path):
    source = _source(tmp_path)
    with sqlite3.connect(source) as conn:
        conn.execute("""CREATE TABLE user_identities (
            provider TEXT, issuer TEXT, subject TEXT, user_id TEXT,
            email_at_link TEXT, email_verified INTEGER, linked_at TEXT,
            PRIMARY KEY (issuer, subject))""")
        conn.execute("""INSERT INTO user_identities VALUES
            ('google', 'https://accounts.google.com', 'google-123',
             'owner-456', 'owner@example.com', 1, '2026-01-01')""")
    original = source.read_bytes()
    approved = _approved(tmp_path, source, [_google()])
    output = tmp_path / "migrated.db"

    with pytest.raises(ValueError):
        prepare_identity_copy(source, approved, output)
    assert source.read_bytes() == original
    assert not output.exists()


def test_exact_existing_mapping_is_idempotent(tmp_path):
    source = _source(tmp_path)
    approved = _approved(tmp_path, source, [_google()])
    first = tmp_path / "first.db"
    assert prepare_identity_copy(source, approved, first) == 1
    second_approved = _approved(tmp_path, first, [_google()])
    second = tmp_path / "second.db"
    assert prepare_identity_copy(first, second_approved, second) == 0
    with sqlite3.connect(second) as conn:
        assert conn.execute("SELECT COUNT(*) FROM user_identities").fetchone()[0] == 1


@pytest.mark.parametrize("mapping,issuer", [
    (_auth0() | {"subject": "full-sub"}, "https://example.auth0.com/"),
    (_auth0(), None),
    (_google() | {"email_verified": "true"}, None),
    (_google() | {"subject": "different"}, None),
    (_google() | {"email_at_link": "Person@Example.com"}, None),
])
def test_rejects_unproven_or_ambiguous_mapping(tmp_path, mapping, issuer):
    source = _source(tmp_path)
    approved = _approved(tmp_path, source, [mapping])
    output = tmp_path / "migrated.db"
    with pytest.raises(ValueError):
        prepare_identity_copy(source, approved, output, auth0_issuer=issuer)
    assert not output.exists()


def test_rejects_configured_application_database_as_source(tmp_path, monkeypatch):
    source = _source(tmp_path)
    approved = _approved(tmp_path, source, [_google()])
    monkeypatch.setenv("SQLITE_DB_PATH", str(source))
    output = tmp_path / "migrated.db"

    with pytest.raises(ValueError):
        prepare_identity_copy(source, approved, output)
    assert not output.exists()


def test_cli_checks_plan_without_writing_until_apply(tmp_path, capsys):
    source = _source(tmp_path)
    approved = _approved(tmp_path, source, [_google()])
    output = tmp_path / "migrated.db"

    assert main([
        "--database", str(source), "--approved-mappings", str(approved),
        "--output", str(output),
    ]) == 0
    assert not output.exists()
    assert json.loads(capsys.readouterr().out) == {
        "new_mappings": 1, "output_created": False,
    }


def test_output_is_not_overwritten(tmp_path):
    source = _source(tmp_path)
    approved = _approved(tmp_path, source, [_google()])
    output = tmp_path / "migrated.db"
    output.write_bytes(b"existing-output")

    with pytest.raises(ValueError):
        prepare_identity_copy(source, approved, output)
    assert output.read_bytes() == b"existing-output"
