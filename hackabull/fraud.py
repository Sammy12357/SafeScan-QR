from __future__ import annotations
import requests
import json
import warnings
import io
import sqlite3
import hashlib
import hmac
import math
import re
import asyncio
import base64
import ipaddress
import secrets
import socket
import time
import csv
from decimal import Decimal, InvalidOperation
from html import escape as escape_html
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qsl
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree

from fastapi import FastAPI, UploadFile, File, Request, Form, Header, Query, Body, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import os
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from db import (
    assert_owns_row,
    clear_rls_context,
    database_path,
    database_storage_status,
    get_conn,
    rls_user_id,
    set_rls_context,
    user_scoped_select,
    unique_email_owner,
    rls_email,
)
from storage import backend_status as storage_backend_status
from storage import download_file as storage_download_file
from storage import object_key as storage_object_key
from storage import upload_bytes as storage_upload_bytes

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration
from .audit import audit_log
from .audit import now_iso
from .config import MALICIOUS_CONTRACT_BLOCKLIST
from .request_helpers import make_id
from .request_helpers import hash_ip
from .request_helpers import request_ip

# =============================================================================
# FRAUD & ABUSE DETECTION (IP / device fingerprint / velocity)
# =============================================================================
def severity_points(severity):
    return {"low": 5, "medium": 20, "high": 50, "critical": 100}.get(severity, 0)

IP_REGISTRY_RETENTION_DAYS = 30
IP_REGISTRY_MAINTENANCE_BATCH = 100
_IP_HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")

def _registry_ip_hash(value):
    # A previous maintenance pass may already have converted this row.
    return value if _IP_HASH_PATTERN.fullmatch(value) else hash_ip(value)

def _upsert_ip_account(conn, ip_hash, user_id, seen_at):
    conn.execute(
        """INSERT INTO ip_registry_accounts (ip_hash, user_id, first_seen, last_seen)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(ip_hash, user_id) DO UPDATE SET
             first_seen = min(first_seen, excluded.first_seen),
             last_seen = max(last_seen, excluded.last_seen)""",
        (ip_hash, user_id, seen_at, seen_at),
    )

def _maintain_ip_registry(conn, batch_limit, *, scrub_flags=True, scrub_audit=True):
    """Fold expired detailed events into account aggregates, then delete them.

    The batch bound keeps normal requests short. A daily maintenance command
    drains all batches so quiet deployments also meet the retention policy.
    """
    cutoff = (datetime.utcnow() - timedelta(days=IP_REGISTRY_RETENTION_DAYS)).isoformat() + "Z"
    rows = conn.execute(
        "SELECT id, ip_address, user_id, created_at FROM ip_registry "
        "WHERE created_at < ? ORDER BY created_at, id LIMIT ?",
        (cutoff, batch_limit),
    ).fetchall()
    for row in rows:
        _upsert_ip_account(conn, _registry_ip_hash(row["ip_address"]), row["user_id"], row["created_at"])
        conn.execute("DELETE FROM ip_registry WHERE id = ?", (row["id"],))

    # Older clustering flags contain the literal address in metadata. Scrub a
    # bounded number per pass without changing their severity or review state.
    if scrub_flags:
        flags = conn.execute(
            "SELECT id, metadata FROM fraud_flags "
            "WHERE check_name IN ('ip_clustering', 'ip_scan_cluster') "
            "AND metadata LIKE '%\"ip\"%' ORDER BY created_at, id LIMIT ?",
            (batch_limit,),
        ).fetchall()
    else:
        flags = []
    for flag in flags:
        try:
            details = json.loads(flag["metadata"] or "{}")
        except (TypeError, ValueError):
            details = {}
        if not isinstance(details, dict):
            details = {}
        raw_ip = details.pop("ip", None)
        if isinstance(raw_ip, str) and raw_ip:
            details["ipHash"] = _registry_ip_hash(raw_ip)
        conn.execute("UPDATE fraud_flags SET metadata = ? WHERE id = ?", (json.dumps(details), flag["id"]))
    if scrub_audit:
        audit_rows = conn.execute(
            "SELECT id FROM audit_logs WHERE ip_address IS NOT NULL AND created_at < ? "
            "ORDER BY created_at, id LIMIT ?",
            (cutoff, batch_limit),
        ).fetchall()
        for audit_row in audit_rows:
            conn.execute("UPDATE audit_logs SET ip_address = NULL WHERE id = ?", (audit_row["id"],))
    else:
        audit_rows = []
    return {"eventsDeleted": len(rows), "flagsRedacted": len(flags), "auditIpsCleared": len(audit_rows)}

def maintain_ip_registry(batch_limit=IP_REGISTRY_MAINTENANCE_BATCH):
    """Process one bounded privacy maintenance batch; safe to call repeatedly."""
    if not isinstance(batch_limit, int) or batch_limit < 1 or batch_limit > 1000:
        raise ValueError("batch_limit must be between 1 and 1000")
    with get_conn() as conn:
        return _maintain_ip_registry(conn, batch_limit)

def register_ip_event(user_id, request, event_type):
    ip_hash = hash_ip(request_ip(request))
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO ip_registry VALUES (?, ?, ?, ?, ?)",
            (make_id("ip"), ip_hash, user_id, event_type, created_at)
        )
        _upsert_ip_account(conn, ip_hash, user_id, created_at)
        _maintain_ip_registry(conn, IP_REGISTRY_MAINTENANCE_BATCH, scrub_flags=False, scrub_audit=False)

def register_device_fingerprint(user_id, fingerprint):
    clean = (fingerprint or "").strip()
    if len(clean) != 64 or not re.fullmatch(r"[a-f0-9]{64}", clean):
        return
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO device_fingerprints VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id, fingerprint) DO UPDATE SET last_seen=excluded.last_seen
            """,
            (make_id("fp"), user_id, clean, now_iso(), now_iso())
        )

def run_fraud_checks(event_type, user_id, request=None, metadata=None):
    """Score an action for abuse and record any fraud signals it trips.

    Looks at things like IP reuse across accounts, device-fingerprint sharing,
    and scan velocity for the given ``event_type`` (e.g. signup, scan, referral),
    persisting flags and returning the signals found so callers can gate rewards
    or require review.
    """
    metadata = metadata or {}
    signals = []
    ip_value = request_ip(request) if request else metadata.get("ip", "")
    user_agent = request.headers.get("user-agent", "") if request else metadata.get("userAgent", "")
    fingerprint = request.headers.get("x-device-fingerprint", "") if request else metadata.get("deviceFingerprint", "")
    fingerprint = fingerprint or metadata.get("deviceFingerprint", "")

    if ip_value:
        register_ip_event(user_id, request, event_type) if request else None
        ip_digest = hash_ip(ip_value)
        with get_conn() as conn:
            since_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            since_1h = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            recent_signups = conn.execute(
                "SELECT COUNT(*) FROM ip_registry WHERE ip_address IN (?, ?) AND event_type = 'signup' AND created_at >= ?",
                (ip_digest, ip_value, since_24h)
            ).fetchone()[0]
            active_scan_accounts = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM ip_registry WHERE ip_address IN (?, ?) AND event_type = 'scan' AND created_at >= ?",
                (ip_digest, ip_value, since_1h)
            ).fetchone()[0]
            lifetime_accounts = conn.execute(
                """SELECT COUNT(*) FROM (
                     SELECT user_id FROM ip_registry_accounts WHERE ip_hash = ?
                     UNION
                     SELECT user_id FROM ip_registry WHERE ip_address IN (?, ?)
                   )""",
                (ip_digest, ip_digest, ip_value)
            ).fetchone()[0]
        if lifetime_accounts > 10:
            signals.append({"checkName": "ip_clustering", "severity": "critical", "autoDisqualify": True, "reason": f"IP has {lifetime_accounts} accounts registered.", "metadata": {"ipHash": ip_digest, "accountCount": lifetime_accounts}})
        elif recent_signups > 3:
            signals.append({"checkName": "ip_clustering", "severity": "high", "autoDisqualify": False, "reason": f"{recent_signups} signups from same IP in 24 hours.", "metadata": {"ipHash": ip_digest, "recentSignups": recent_signups}})
        elif event_type == "scan" and active_scan_accounts > 2:
            signals.append({"checkName": "ip_scan_cluster", "severity": "medium", "autoDisqualify": False, "reason": f"{active_scan_accounts} active scan accounts share one IP in the last hour.", "metadata": {"ipHash": ip_digest, "activeScanAccounts": active_scan_accounts}})

    if event_type == "scan":
        with get_conn() as conn:
            conn.row_factory = sqlite3.Row
            velocity = conn.execute("SELECT * FROM scan_velocity WHERE user_id = ?", (user_id,)).fetchone()
            now = datetime.utcnow()
            last_scan_at = None
            if velocity and velocity["last_scan_at"]:
                try:
                    last_scan_at = datetime.fromisoformat(str(velocity["last_scan_at"]).replace("Z", ""))
                except ValueError:
                    last_scan_at = None
            seconds_since = (now - last_scan_at).total_seconds() if last_scan_at else 999
            scans_last_hour = (velocity["scans_last_hour"] if velocity else 0) + 1
            scans_last_day = (velocity["scans_last_day"] if velocity else 0) + 1
            duplicate_count = ((velocity["duplicate_count"] if velocity else 0) + 1) if metadata.get("url") and velocity and metadata.get("url") == velocity["last_scan_url"] else 0
            fast_count = ((velocity["fast_scan_count"] if velocity else 0) + 1) if seconds_since < 3 else 0
            conn.execute(
                """
                INSERT INTO scan_velocity VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                  scans_last_hour=excluded.scans_last_hour,
                  scans_last_day=excluded.scans_last_day,
                  last_scan_at=excluded.last_scan_at,
                  last_scan_url=excluded.last_scan_url,
                  duplicate_count=excluded.duplicate_count,
                  fast_scan_count=excluded.fast_scan_count,
                  updated_at=excluded.updated_at
                """,
                (user_id, scans_last_hour, scans_last_day, now_iso(), metadata.get("url"), duplicate_count, fast_count, now_iso())
            )
        if scans_last_hour > 60 or fast_count >= 10:
            signals.append({"checkName": "scan_velocity", "severity": "critical" if fast_count >= 10 else "high", "autoDisqualify": fast_count >= 10, "reason": "Bot-like scan velocity detected.", "metadata": {"scansLastHour": scans_last_hour, "secondsSinceLastScan": seconds_since, "fastScanCount": fast_count}})
        elif scans_last_hour > 20:
            signals.append({"checkName": "scan_velocity", "severity": "medium", "autoDisqualify": False, "reason": f"{scans_last_hour} scans in the last hour.", "metadata": {"scansLastHour": scans_last_hour}})
        if duplicate_count > 3:
            signals.append({"checkName": "duplicate_url_scans", "severity": "medium", "autoDisqualify": False, "reason": "Same URL scanned repeatedly.", "metadata": {"duplicateCount": duplicate_count, "url": metadata.get("url")}})

    if fingerprint:
        register_device_fingerprint(user_id, fingerprint)
        with get_conn() as conn:
            shared_users = conn.execute("SELECT COUNT(DISTINCT user_id) FROM device_fingerprints WHERE fingerprint = ?", (fingerprint,)).fetchone()[0]
        if shared_users > 5:
            signals.append({"checkName": "device_fingerprint", "severity": "critical", "autoDisqualify": True, "reason": f"Device fingerprint is shared by {shared_users} accounts.", "metadata": {"sharedUsers": shared_users}})
        elif shared_users > 2:
            signals.append({"checkName": "device_fingerprint", "severity": "high", "autoDisqualify": False, "reason": f"Device fingerprint is shared by {shared_users} accounts.", "metadata": {"sharedUsers": shared_users}})

    if event_type == "wallet_connect" and metadata.get("walletAddress"):
        wallet = metadata["walletAddress"]
        with get_conn() as conn:
            existing = conn.execute(
                """
                SELECT user_id FROM wallets WHERE address = ? AND user_id != ? AND verified = 1
                UNION
                SELECT email FROM scans WHERE wallet_address = ? AND email != ?
                LIMIT 1
                """,
                (wallet, user_id, wallet, user_id)
            ).fetchone()
        if existing:
            signals.append({"checkName": "wallet_reuse", "severity": "critical", "autoDisqualify": True, "reason": f"Wallet {wallet[:8]}... already linked to another account.", "metadata": {"walletAddress": wallet, "existingUser": existing[0]}})
        elif wallet.lower() in {item.lower() for item in MALICIOUS_CONTRACT_BLOCKLIST}:
            signals.append({"checkName": "wallet_blocklist", "severity": "high", "autoDisqualify": False, "reason": "Wallet appears on the SafeScan blocklist.", "metadata": {"walletAddress": wallet}})
        if metadata.get("txCount") == 0:
            signals.append({"checkName": "wallet_zero_activity", "severity": "medium", "autoDisqualify": False, "reason": "Wallet has no recent Solana mainnet activity.", "metadata": {"walletAddress": wallet}})
        if metadata.get("walletAgeDays") is not None and int(metadata.get("walletAgeDays") or 0) < 7:
            signals.append({"checkName": "new_wallet", "severity": "medium", "autoDisqualify": False, "reason": "Wallet appears to be less than 7 days old.", "metadata": {"walletAddress": wallet, "walletAgeDays": metadata.get("walletAgeDays")}})

    if signals:
        new_points = sum(severity_points(item["severity"]) for item in signals)
        account_id = rls_user_id() if user_id == rls_email() else None
        if not account_id:
            with get_conn() as conn:
                direct = conn.execute("SELECT google_id FROM users WHERE google_id = ?", (user_id,)).fetchone()
                account_id = direct[0] if direct else None
        if not account_id:
            account_id = lookup_user_id_by_email(user_id)
        with get_conn() as conn:
            for item in signals:
                conn.execute(
                    "INSERT INTO fraud_flags VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?)",
                    (make_id("fraud"), user_id, item["checkName"], item["severity"], item["reason"], json.dumps(item["metadata"]), int(item["autoDisqualify"]), now_iso())
                )
            if account_id:
                conn.execute("UPDATE users SET fraud_score = COALESCE(fraud_score, 0) + ?, airdrop_status = CASE WHEN COALESCE(fraud_score, 0) + ? >= 40 THEN 'flagged' ELSE airdrop_status END WHERE google_id = ?", (new_points, new_points, account_id))
        audit_log("fraud.flags_added", request=request, actor_user_id=account_id, target_type="user", target_id=account_id, metadata={"signalCount": len(signals), "points": new_points})
    return signals

def lookup_user_id_by_email(email):
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        return None
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT google_id FROM users WHERE lower(email) = ? AND status != 'deleted'",
            (normalized_email,),
        ).fetchall()
        if len(rows) == 1 and unique_email_owner(conn, email, rows[0]["google_id"]):
            return rows[0]["google_id"]
    return None

SCAN_CLASSIFICATIONS = (
    ("MALICIOUS", "Dangerous"),
    ("CAUTION", "Needs Review"),
    ("SAFE", "Safe"),
    ("UNKNOWN", "Unknown"),
)

SCAN_CLASSIFICATION_LABELS = dict(SCAN_CLASSIFICATIONS)
SCAN_HISTORY_MAX_SIGNALS = 4
SCAN_HISTORY_MAX_SIGNAL_TEXT = 120

