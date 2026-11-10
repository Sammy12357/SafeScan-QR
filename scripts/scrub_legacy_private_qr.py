#!/usr/bin/env python3
"""Dry-run-first cleanup of private QR data stored by older SafeScan releases.

This script changes SQLite only. It deliberately does not delete uploaded QR
objects: operators must back up and purge those separately under a retention
decision. Run while the service is stopped or in a maintenance window.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path


CONFIRMATION = "SCRUB PRIVATE QR DATA"
GENERIC_SCAN_LIST = "[Scan payload list hidden]"
GENERIC_SIGNAL = json.dumps([{
    "label": "Non-URL QR action",
    "severity": "medium",
    "detail": "Payload details were removed from scan history to protect private data.",
}], separators=(",", ":"))


def is_web_url(value: str | None) -> bool:
    return str(value or "").strip().lower().startswith(("https://", "http://"))


def is_redacted(value: str | None) -> bool:
    value = str(value or "")
    return value.startswith("[") and ("QR payload redacted" in value or "QR blocklist entry redacted" in value)


def needs_scrub(value: str | None) -> bool:
    return bool(value) and not is_web_url(value) and not is_redacted(value)


def payload_label(value: str) -> str:
    upper = value.strip().upper()
    if upper.startswith("WIFI:"):
        return "Wi-Fi"
    if upper.startswith("OTPAUTH:"):
        return "Authentication"
    if upper.startswith(("WC:", "UPI:", "BITCOIN:", "ETHEREUM:", "SOLANA:")):
        return "Crypto/payment"
    if upper.startswith(("SMS:", "SMSTO:")):
        return "SMS"
    if upper.startswith("MAILTO:"):
        return "Email"
    if "BEGIN:VCARD" in upper:
        return "Contact card"
    if upper.startswith("TEL:"):
        return "Phone"
    if upper.startswith("INTENT:"):
        return "App/deep link"
    if upper.startswith("BEGIN:VEVENT") or "BEGIN:VCALENDAR" in upper:
        return "Calendar"
    return "Non-URL"


def fingerprint_key() -> bytes:
    for name in ("QR_PAYLOAD_FINGERPRINT_KEY", "AIRDROP_ADMIN_SECRET"):
        candidate = os.getenv(name, "").encode("utf-8")
        if len(candidate) >= 32:
            return candidate
    raise ValueError("Execution requires QR_PAYLOAD_FINGERPRINT_KEY or AIRDROP_ADMIN_SECRET with at least 32 bytes.")


def private_reference(raw: str, owner: str, key: bytes) -> str:
    if not needs_scrub(raw):
        return raw
    message = b"safescan-private-qr-v1\0" + (owner or "").encode("utf-8") + b"\0" + raw.strip().encode("utf-8")
    digest = hmac.new(key, message, hashlib.sha256).hexdigest()[:32]
    return f"[{payload_label(raw)} QR payload redacted; ref {digest}]"


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def rows(conn: sqlite3.Connection, table: str, columns: str):
    if not table_exists(conn, table):
        return []
    return conn.execute(f"SELECT rowid, {columns} FROM {table}").fetchall()


def private_fraud_metadata(value: str | None) -> bool:
    try:
        metadata = json.loads(value or "{}")
    except (TypeError, ValueError):
        return False
    return isinstance(metadata, dict) and needs_scrub(metadata.get("url"))


def preview(conn: sqlite3.Connection, cache_path: Path | None = None) -> dict[str, int]:
    counts = {
        "scan_history": sum(needs_scrub(row[1]) for row in rows(conn, "scan_history", "url")),
        "scans": sum(bool(row[1]) and row[1] != GENERIC_SCAN_LIST for row in rows(conn, "scans", "url_found")),
        "scan_events": sum(needs_scrub(row[1]) for row in rows(conn, "scan_events", "url_found")),
        "scan_velocity": sum(needs_scrub(row[1]) for row in rows(conn, "scan_velocity", "last_scan_url")),
        "fraud_flags": sum(private_fraud_metadata(row[1]) for row in rows(conn, "fraud_flags", "metadata")),
        "url_blocklist": sum(needs_scrub(row[1]) for row in rows(conn, "url_blocklist", "url")),
        "upload_artifacts_manual_cleanup": 0,
        "ml_cache_disposable_rows": 0,
    }
    if table_exists(conn, "upload_artifacts"):
        counts["upload_artifacts_manual_cleanup"] = conn.execute(
            "SELECT COUNT(*) FROM upload_artifacts WHERE object_key LIKE 'qr-uploads/%'"
        ).fetchone()[0]
    if cache_path and cache_path.exists():
        with sqlite3.connect(f"file:{cache_path}?mode=ro", uri=True) as cache:
            if table_exists(cache, "ml_cache"):
                counts["ml_cache_disposable_rows"] = cache.execute("SELECT COUNT(*) FROM ml_cache").fetchone()[0]
    return counts


def verified_backup(source: sqlite3.Connection, backup_path: Path) -> None:
    if backup_path.exists():
        raise ValueError("Backup path already exists; choose a new path so no backup is overwritten.")
    if not backup_path.parent.is_dir():
        raise ValueError("Backup parent directory must already exist.")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(backup_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    with sqlite3.connect(backup_path) as backup:
        backup.execute("PRAGMA journal_mode=OFF")
        source.backup(backup)
        if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("Backup integrity check failed; no cleanup was started.")
    if stat.S_IMODE(backup_path.stat().st_mode) != 0o600:
        raise RuntimeError("Backup permissions are not owner-only; no cleanup was started.")


def scrub_database(conn: sqlite3.Connection, key: bytes) -> None:
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("BEGIN IMMEDIATE")
    try:
        for rowid, raw, user_id, email, score in rows(conn, "scan_history", "url, user_id, email, risk_score"):
            if needs_scrub(raw):
                conn.execute(
                    "UPDATE scan_history SET url=?, signals=? WHERE rowid=?",
                    (private_reference(raw, user_id or email or "", key), GENERIC_SIGNAL, rowid),
                )
        for rowid, raw in rows(conn, "scans", "url_found"):
            if raw and raw != GENERIC_SCAN_LIST:
                conn.execute("UPDATE scans SET url_found=? WHERE rowid=?", (GENERIC_SCAN_LIST, rowid))
        for rowid, raw, user_id, email in rows(conn, "scan_events", "url_found, user_id, email"):
            if needs_scrub(raw):
                ref = private_reference(raw, user_id or email or "", key)
                digest = hashlib.sha256(ref.encode("utf-8")).hexdigest()
                conflict = conn.execute(
                    "SELECT 1 FROM scan_events WHERE email=? AND payload_hash=? AND rowid!=?",
                    (email, digest, rowid),
                ).fetchone()
                if conflict:
                    conn.execute("DELETE FROM scan_events WHERE rowid=?", (rowid,))
                else:
                    conn.execute("UPDATE scan_events SET url_found=?, payload_hash=? WHERE rowid=?", (ref, digest, rowid))
        for rowid, raw, user_id in rows(conn, "scan_velocity", "last_scan_url, user_id"):
            if needs_scrub(raw):
                conn.execute("UPDATE scan_velocity SET last_scan_url=? WHERE rowid=?", (private_reference(raw, user_id or "", key), rowid))
        for rowid, value, user_id, check_name in rows(conn, "fraud_flags", "metadata, user_id, check_name"):
            try:
                metadata = json.loads(value or "{}")
            except (TypeError, ValueError):
                if check_name == "duplicate_url_scans":
                    conn.execute("UPDATE fraud_flags SET metadata='{}' WHERE rowid=?", (rowid,))
                continue
            if isinstance(metadata, dict) and needs_scrub(metadata.get("url")):
                metadata["url"] = private_reference(metadata["url"], user_id or "", key)
                conn.execute("UPDATE fraud_flags SET metadata=? WHERE rowid=?", (json.dumps(metadata, separators=(",", ":")), rowid))
        removed_at = datetime.now(timezone.utc).isoformat()
        for rowid, raw in rows(conn, "url_blocklist", "url"):
            if needs_scrub(raw):
                conn.execute(
                    "UPDATE url_blocklist SET url=?, removed_at=COALESCE(removed_at, ?) WHERE rowid=?",
                    (f"[Non-URL QR blocklist entry redacted; id {rowid}]", removed_at, rowid),
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    conn.execute("VACUUM")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def scrub_cache(cache_path: Path) -> None:
    if not cache_path.exists():
        return
    with sqlite3.connect(cache_path) as cache:
        if not table_exists(cache, "ml_cache"):
            return
        cache.execute("PRAGMA secure_delete=ON")
        cache.execute("DELETE FROM ml_cache")
        cache.commit()
        cache.execute("VACUUM")
        cache.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True, type=Path, help="SQLite service database path")
    parser.add_argument("--ml-cache", type=Path, help="ML cache path; defaults to a sibling ml_cache.sqlite")
    parser.add_argument("--execute", action="store_true", help="Apply cleanup after backing up and verifying")
    parser.add_argument("--backup", type=Path, help="New backup file path (required with --execute)")
    parser.add_argument("--confirm", default="", help=f"Exact confirmation phrase: {CONFIRMATION}")
    args = parser.parse_args(argv)
    database = args.database.resolve()
    if not database.is_file():
        parser.error("Database file does not exist.")
    cache_path = (args.ml_cache or database.with_name("ml_cache.sqlite")).resolve()
    if args.execute:
        if args.confirm != CONFIRMATION or args.backup is None:
            parser.error("--execute requires --backup and the exact --confirm phrase.")
        backup = args.backup.resolve()
        if backup == database or backup == cache_path:
            parser.error("Backup path must differ from the database and ML cache.")
        cache_backup = backup.with_name(backup.name + ".ml-cache.sqlite")
        if backup.exists() or (cache_path.exists() and cache_backup.exists()):
            parser.error("A backup path already exists; choose a new backup name.")
        key = fingerprint_key()
    with sqlite3.connect(database) as conn:
        conn.row_factory = sqlite3.Row
        before = preview(conn, cache_path)
        print(json.dumps({"mode": "dry-run" if not args.execute else "before", "counts": before}, sort_keys=True))
        if not args.execute:
            return 0
        verified_backup(conn, backup)
        if cache_path.exists():
            with sqlite3.connect(cache_path) as cache:
                verified_backup(cache, cache_backup)
        scrub_database(conn, key)
        scrub_cache(cache_path)
        after = preview(conn, cache_path)
        print(json.dumps({"mode": "complete", "counts": after, "uploads": "manual cleanup required"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"Cleanup stopped: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
