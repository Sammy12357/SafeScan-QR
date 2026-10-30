"""Operator cleanup is explicit, backed up, idempotent, and quiet about data."""

import hashlib
import importlib.util
import json
import sqlite3
import stat
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scrub_legacy_private_qr.py"
SPEC = importlib.util.spec_from_file_location("scrub_legacy_private_qr", SCRIPT)
CLEANUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLEANUP)


def sample_databases(tmp_path):
    db_path = tmp_path / "app.db"
    cache_path = tmp_path / "ml_cache.sqlite"
    secret = "LEGACY_QR_SECRET_87654321"
    raw = f"otpauth://totp/Test?secret={secret}"
    with sqlite3.connect(db_path) as conn:
        conn.executescript("""
            CREATE TABLE scan_history (id TEXT, url TEXT, signals TEXT, user_id TEXT, email TEXT, risk_score INTEGER);
            CREATE TABLE scans (email TEXT, url_found TEXT, scan_count INTEGER);
            CREATE TABLE scan_events (email TEXT, payload_hash TEXT, url_found TEXT, user_id TEXT, UNIQUE(email, payload_hash));
            CREATE TABLE scan_velocity (user_id TEXT, last_scan_url TEXT);
            CREATE TABLE fraud_flags (user_id TEXT, check_name TEXT, metadata TEXT);
            CREATE TABLE url_blocklist (url TEXT UNIQUE, removed_at TEXT);
            CREATE TABLE upload_artifacts (object_key TEXT);
        """)
        conn.execute("INSERT INTO scan_history VALUES (?, ?, ?, ?, ?, ?)", ("one", raw, json.dumps([{"detail": raw}]), "user-1", "user@example.com", 65))
        conn.execute("INSERT INTO scan_history VALUES (?, ?, ?, ?, ?, ?)", ("two", "https://example.com/", "[]", "user-1", "user@example.com", 8))
        conn.execute("INSERT INTO scans VALUES (?, ?, ?)", ("user@example.com", f"https://example.com/,{raw}", 2))
        conn.execute("INSERT INTO scan_events VALUES (?, ?, ?, ?)", ("user@example.com", hashlib.sha256(raw.encode()).hexdigest(), raw, "user-1"))
        conn.execute("INSERT INTO scan_velocity VALUES (?, ?)", ("user-1", raw))
        conn.execute("INSERT INTO fraud_flags VALUES (?, ?, ?)", ("user-1", "duplicate_url_scans", json.dumps({"url": raw, "duplicateCount": 4})))
        conn.execute("INSERT INTO url_blocklist VALUES (?, NULL)", (raw,))
        conn.execute("INSERT INTO upload_artifacts VALUES ('qr-uploads/2026/10/30/guest/private.png')")
    with sqlite3.connect(cache_path) as conn:
        conn.execute("CREATE TABLE ml_cache (url_key TEXT, payload TEXT, cached_at INTEGER)")
        conn.execute("INSERT INTO ml_cache VALUES (?, '{}', 1)", (raw,))
    return db_path, cache_path, raw, secret


def test_cleanup_dry_run_and_explicit_backed_up_execution(tmp_path, monkeypatch, capsys):
    db_path, cache_path, raw, secret = sample_databases(tmp_path)
    args = ["--database", str(db_path), "--ml-cache", str(cache_path)]

    assert CLEANUP.main(args) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["mode"] == "dry-run"
    assert preview["counts"]["scan_history"] == 1
    assert preview["counts"]["upload_artifacts_manual_cleanup"] == 1
    assert secret not in json.dumps(preview)
    assert secret.encode() in db_path.read_bytes()

    with pytest.raises(SystemExit):
        CLEANUP.main(args + ["--execute"])
    assert secret.encode() in db_path.read_bytes()

    backup_dir = tmp_path / "protected-backups"
    backup_dir.mkdir()
    backup_path = backup_dir / "before.db"
    monkeypatch.setenv("QR_PAYLOAD_FINGERPRINT_KEY", "s" * 32)
    assert CLEANUP.main(args + ["--execute", "--backup", str(backup_path), "--confirm", CLEANUP.CONFIRMATION]) == 0
    completed = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    assert completed[-1]["mode"] == "complete"
    assert completed[-1]["counts"]["scan_history"] == 0
    assert completed[-1]["counts"]["upload_artifacts_manual_cleanup"] == 1
    assert secret not in json.dumps(completed)
    assert secret.encode() in backup_path.read_bytes()
    assert stat.S_IMODE(backup_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((backup_dir / "before.db.ml-cache.sqlite").stat().st_mode) == 0o600
    assert secret.encode() not in db_path.read_bytes()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT scan_count FROM scans").fetchone()[0] == 2
        assert conn.execute("SELECT url_found FROM scans").fetchone()[0] == CLEANUP.GENERIC_SCAN_LIST
        event = conn.execute("SELECT url_found, payload_hash FROM scan_events").fetchone()
        assert event[0].startswith("[Authentication QR payload redacted;")
        assert event[1] != hashlib.sha256(raw.encode()).hexdigest()
        assert conn.execute("SELECT removed_at FROM url_blocklist").fetchone()[0]
        assert conn.execute("SELECT COUNT(*) FROM upload_artifacts").fetchone()[0] == 1
    with sqlite3.connect(cache_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM ml_cache").fetchone()[0] == 0

    # A second dry run finds no private DB values to migrate.
    assert CLEANUP.main(args) == 0
    second = json.loads(capsys.readouterr().out)
    assert all(value == 0 for key, value in second["counts"].items() if key != "upload_artifacts_manual_cleanup")


def test_cleanup_rejects_weak_key_before_backing_up_or_mutating(tmp_path, monkeypatch):
    db_path, cache_path, _, secret = sample_databases(tmp_path)
    backup = tmp_path / "backup.db"
    monkeypatch.setenv("QR_PAYLOAD_FINGERPRINT_KEY", "weak")
    monkeypatch.delenv("AIRDROP_ADMIN_SECRET", raising=False)

    with pytest.raises(ValueError, match="at least 32 bytes"):
        CLEANUP.main([
            "--database", str(db_path), "--ml-cache", str(cache_path), "--execute",
            "--backup", str(backup), "--confirm", CLEANUP.CONFIRMATION,
        ])

    assert not backup.exists()
    assert secret.encode() in db_path.read_bytes()


def test_cleanup_never_overwrites_existing_backup(tmp_path, monkeypatch):
    db_path, cache_path, _, secret = sample_databases(tmp_path)
    backup = tmp_path / "existing-backup.db"
    backup.write_bytes(b"protected backup")
    monkeypatch.setenv("QR_PAYLOAD_FINGERPRINT_KEY", "s" * 32)

    with pytest.raises(SystemExit):
        CLEANUP.main([
            "--database", str(db_path), "--ml-cache", str(cache_path), "--execute",
            "--backup", str(backup), "--confirm", CLEANUP.CONFIRMATION,
        ])

    assert backup.read_bytes() == b"protected backup"
    assert secret.encode() in db_path.read_bytes()
