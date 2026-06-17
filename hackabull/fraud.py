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
from .request_helpers import request_ip

# =============================================================================
# FRAUD & ABUSE DETECTION (IP / device fingerprint / velocity)
# =============================================================================
def severity_points(severity):
    return {"low": 5, "medium": 20, "high": 50, "critical": 100}.get(severity, 0)

def register_ip_event(user_id, request, event_type):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO ip_registry VALUES (?, ?, ?, ?, ?)",
            (make_id("ip"), request_ip(request), user_id, event_type, now_iso())
        )

def register_device_fingerprint(user_id, fingerprint):
    clean = (fingerprint or "").strip()
    if not re.fullmatch(r"[a-f0-9]{64}", clean):
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
        with get_conn() as conn:
            since_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
            since_1h = (datetime.utcnow() - timedelta(hours=1)).isoformat()
            recent_signups = conn.execute(
                "SELECT COUNT(*) FROM ip_registry WHERE ip_address = ? AND event_type = 'signup' AND created_at >= ?",
                (ip_value, since_24h)
            ).fetchone()[0]
            active_scan_accounts = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM ip_registry WHERE ip_address = ? AND event_type = 'scan' AND created_at >= ?",
                (ip_value, since_1h)
            ).fetchone()[0]
            lifetime_accounts = conn.execute(
                "SELECT COUNT(DISTINCT user_id) FROM ip_registry WHERE ip_address = ?",
                (ip_value,)
            ).fetchone()[0]
        if lifetime_accounts > 10:
            signals.append({"checkName": "ip_clustering", "severity": "critical", "autoDisqualify": True, "reason": f"IP has {lifetime_accounts} accounts registered.", "metadata": {"ip": ip_value, "accountCount": lifetime_accounts}})
        elif recent_signups > 3:
            signals.append({"checkName": "ip_clustering", "severity": "high", "autoDisqualify": False, "reason": f"{recent_signups} signups from same IP in 24 hours.", "metadata": {"ip": ip_value, "recentSignups": recent_signups}})
        elif event_type == "scan" and active_scan_accounts > 2:
            signals.append({"checkName": "ip_scan_cluster", "severity": "medium", "autoDisqualify": False, "reason": f"{active_scan_accounts} active scan accounts share one IP in the last hour.", "metadata": {"ip": ip_value, "activeScanAccounts": active_scan_accounts}})

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
        with get_conn() as conn:
            for item in signals:
                conn.execute(
                    "INSERT INTO fraud_flags VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, ?)",
                    (make_id("fraud"), user_id, item["checkName"], item["severity"], item["reason"], json.dumps(item["metadata"]), int(item["autoDisqualify"]), now_iso())
                )
            conn.execute("UPDATE users SET fraud_score = COALESCE(fraud_score, 0) + ?, airdrop_status = CASE WHEN COALESCE(fraud_score, 0) + ? >= 40 THEN 'flagged' ELSE airdrop_status END WHERE email = ? OR google_id = ?", (new_points, new_points, user_id, user_id))
        audit_log("fraud.flags_added", request=request, actor_user_id=user_id, target_type="user", target_id=user_id, metadata={"signalCount": len(signals), "points": new_points})
    return signals

def lookup_user_id_by_email(email):
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        return None
    with get_conn() as conn:
        row = conn.execute(
            "SELECT google_id FROM users WHERE lower(email) = ? AND status != 'deleted' ORDER BY created_at LIMIT 1",
            (normalized_email,),
        ).fetchone()
    return row["google_id"] if row else None

SCAN_CLASSIFICATIONS = (
    ("MALICIOUS", "Dangerous"),
    ("CAUTION", "Needs Review"),
    ("SAFE", "Safe"),
    ("UNKNOWN", "Unknown"),
)

SCAN_CLASSIFICATION_LABELS = dict(SCAN_CLASSIFICATIONS)
SCAN_HISTORY_MAX_SIGNALS = 4
SCAN_HISTORY_MAX_SIGNAL_TEXT = 120

