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
from .audit import SafeScanError
from .audit import now_iso
from .config import APP_URL
from .config import LOCAL_AUTH_ENABLED
from .config import ML_MODEL_ENABLED
from .config import ML_MODEL_OBJECT_KEY
from .config import ML_MODEL_PATH
from .config import QR_UPLOADS
from .fraud import SCAN_CLASSIFICATIONS
from .fraud import SCAN_CLASSIFICATION_LABELS
from .fraud import SCAN_HISTORY_MAX_SIGNALS
from .fraud import SCAN_HISTORY_MAX_SIGNAL_TEXT
from .fraud import lookup_user_id_by_email
from .request_helpers import make_id
from .scoring import status_from_risk

# =============================================================================
# SCAN HISTORY: CLASSIFICATION & PERSISTENCE
# =============================================================================
def scan_classification(verdict=None, risk_score=0, overall_risk=None):
    normalized_verdict = str(verdict or "").strip().upper()
    normalized_risk = str(overall_risk or "").strip().lower()
    try:
        score = int(risk_score or 0)
    except (TypeError, ValueError):
        score = 0
    if normalized_verdict in ("MALICIOUS", "HIGH", "DANGER") or normalized_risk == "high" or score >= 80:
        return "MALICIOUS"
    if normalized_verdict in ("CAUTION", "SUSPICIOUS", "MEDIUM") or normalized_risk == "suspicious" or score >= 40:
        return "CAUTION"
    if normalized_verdict == "SAFE" or normalized_risk == "safe" or score < 40:
        return "SAFE"
    return "UNKNOWN"

def scan_classification_from_analysis(analysis):
    score = analysis.get("score") or analysis.get("confidenceScore") or 0
    verdict = analysis.get("status")
    return scan_classification(verdict, score, analysis.get("overallRisk"))

def scan_classification_from_row(row):
    stored = (row["classification"] if "classification" in row.keys() else "") if hasattr(row, "keys") else row.get("classification", "")
    stored = str(stored or "").strip().upper()
    if stored in SCAN_CLASSIFICATION_LABELS:
        return stored
    verdict = row["verdict"] if hasattr(row, "keys") else row.get("verdict")
    risk_score = row["risk_score"] if hasattr(row, "keys") else row.get("risk_score")
    return scan_classification(verdict, risk_score)

def compact_text(value, limit=SCAN_HISTORY_MAX_SIGNAL_TEXT):
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "..."

def compact_scan_signals(analysis):
    raw_signals = analysis.get("reasons") or analysis.get("signals") or []
    if not isinstance(raw_signals, list):
        return []

    def signal_rank(item):
        severity = str(item.get("severity") or "").lower() if isinstance(item, dict) else ""
        return {"high": 0, "critical": 0, "medium": 1, "low": 2}.get(severity, 3)

    compacted = []
    for item in sorted([entry for entry in raw_signals if isinstance(entry, dict)], key=signal_rank)[:SCAN_HISTORY_MAX_SIGNALS]:
        label = item.get("label") or item.get("check") or item.get("checkName") or item.get("name") or "Signal"
        severity = str(item.get("severity") or "low").lower()
        detail = item.get("detail") or item.get("description") or item.get("reason") or item.get("summary") or ""
        compacted.append({
            "label": compact_text(label, 48),
            "severity": severity if severity in ("critical", "high", "medium", "low") else "low",
            "detail": compact_text(detail),
        })
    return compacted

def serialize_scan_history_row(row):
    try:
        signals = json.loads(row["signals"] or "[]")
    except (TypeError, json.JSONDecodeError):
        signals = []
    classification = scan_classification_from_row(row)
    return {
        "scanId": row["id"],
        "id": row["id"],
        "url": row["url"],
        "verdict": row["verdict"] or classification.lower(),
        "classification": classification,
        "classificationLabel": SCAN_CLASSIFICATION_LABELS.get(classification, "Unknown"),
        "threat_type": classification,
        "riskScore": int(row["risk_score"] or 0),
        "risk_score": int(row["risk_score"] or 0),
        "signals": signals if isinstance(signals, list) else [],
        "reported": bool(row["reported"]),
        "scannedAt": row["created_at"],
        "analyzedAt": row["created_at"],
        "created_at": row["created_at"],
    }

def group_scan_history(items):
    by_classification = {key: [] for key, _ in SCAN_CLASSIFICATIONS}
    for item in items:
        by_classification.setdefault(item["classification"], []).append(item)
    return [
        {
            "classification": key,
            "label": label,
            "count": len(by_classification.get(key, [])),
            "scans": by_classification.get(key, []),
        }
        for key, label in SCAN_CLASSIFICATIONS
        if by_classification.get(key)
    ]

def save_scan_history(email, url, analysis, reported=False, user_id=None):
    """Persist one completed scan to the per-user history table.

    Stores a compacted form of the analysis (verdict, score, key signals) keyed
    by both email and resolved user_id so the user's history is retrievable
    regardless of how they signed in.
    """
    normalized_email = (email or "").strip().lower()
    resolved_user_id = user_id or lookup_user_id_by_email(normalized_email)
    risk_score = int(analysis.get("score") or analysis.get("confidenceScore") or 0)
    verdict = analysis.get("status") or status_from_risk(analysis.get("overallRisk"))
    classification = scan_classification_from_analysis(analysis)
    compact_signals = compact_scan_signals(analysis)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at, user_id, classification) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                make_id("scan"),
                normalized_email,
                url[:2048],
                risk_score,
                verdict,
                json.dumps(compact_signals, separators=(",", ":")),
                int(reported),
                now_iso(),
                resolved_user_id,
                classification,
            )
        )


def save_user_scan(user_id, url, analysis, email=None, reported=False):
    resolved_email = (email or "").strip().lower()
    if not resolved_email and user_id:
        with get_conn() as conn:
            row = conn.execute("SELECT email FROM users WHERE google_id = ?", (user_id,)).fetchone()
            resolved_email = (row["email"] if row else "").strip().lower()
    if not resolved_email:
        raise SafeScanError("A user email is required to save scan history.", 400)
    risk_score = int(analysis.get("score") or analysis.get("confidenceScore") or 0)
    verdict = analysis.get("status") or status_from_risk(analysis.get("overallRisk"))
    classification = scan_classification_from_analysis(analysis)
    compact_signals = compact_scan_signals(analysis)
    with get_conn() as conn:
        scan_id = make_id("scan")
        conn.execute(
            "INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at, user_id, classification) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                resolved_email,
                url[:2048],
                risk_score,
                verdict,
                json.dumps(compact_signals, separators=(",", ":")),
                int(reported),
                now_iso(),
                user_id,
                classification,
            ),
        )
    return scan_id


def get_user_scan_history(user_id, limit=100):
    bounded_limit = max(1, min(int(limit or 100), 500))
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT *, verdict AS threat_type
            FROM scan_history
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (user_id, bounded_limit),
        ).fetchall()
    return [dict(row) for row in rows]


def persist_qr_upload(content: bytes, filename: str, content_type: str, user: dict | None):
    if not content:
        return None
    user_id = (user or {}).get("google_id") or (user or {}).get("email")
    email = (user or {}).get("email")
    key = storage_object_key("qr-uploads", filename or "upload.bin", user_id, content)
    artifact = storage_upload_bytes(content, key, content_type or "application/octet-stream")
    digest = hashlib.sha256(content).hexdigest()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO upload_artifacts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                make_id("upload"),
                user_id,
                email,
                artifact["key"],
                artifact["backend"],
                content_type or "application/octet-stream",
                len(content),
                digest,
                now_iso(),
            ),
        )
    QR_UPLOADS.labels(backend=artifact["backend"]).inc()
    return artifact


def ensure_ml_model_available():
    if not ML_MODEL_ENABLED or os.path.exists(ML_MODEL_PATH):
        return
    if not ML_MODEL_OBJECT_KEY:
        return
    try:
        storage_download_file(ML_MODEL_OBJECT_KEY, ML_MODEL_PATH)
    except Exception as exc:
        print({"warning": "ML model download failed", "error": str(exc)})


def plain_action(action):
    labels = {
        "user.login": "User logged in",
        "user.logout": "User signed out",
        "auth.failed": "Authentication failed",
        "auth.permission_denied": "Permission denied",
        "qr.scanned": "QR scan recorded",
        "wallet.nonce_issued": "Wallet challenge issued",
        "wallet.verification_failed": "Wallet verification failed",
        "wallet.connected": "Wallet connected",
        "wallet.disconnected": "Wallet disconnected",
        "wallet.onchain_verified": "Wallet on-chain metadata refreshed",
        "fraud.flags_added": "Fraud signals added",
        "admin.user_suspended": "Admin suspended user",
        "admin.user_unsuspended": "Admin unsuspended user",
        "admin.user_deleted": "Owner deleted user",
        "admin.role_changed": "Owner changed user role",
        "admin.export": "Admin exported data",
        "admin.report_reviewed": "Admin reviewed URL report",
        "api_key.created": "Owner created API key",
        "api_key.revoked": "Owner revoked API key",
    }
    return labels.get(action, action.replace("_", " ").replace(".", " ").title())

def admin_avatar(email):
    initials = "".join(part[:1].upper() for part in (email or "A").split("@")[0].split(".")[:2]) or "A"
    return initials

def index_user_context(user):
    role = user.get("role", "guest") if user else "guest"
    email = user.get("email", "") if user else ""
    username = (user.get("username") or "").strip() if user else ""
    display_name = (user.get("display_name") or "").strip() if user else ""
    return {
        "user_role": role,
        "is_admin": role in ("admin", "owner"),
        "is_owner": role == "owner",
        "username": user.get("username") if user else "",
        "profile_display_name": "Safe Scanner",
        "profile_subtitle": username or display_name or email,
        "profile_picture": user.get("picture") if user else "",
        # Used by index.html to enable Google One Tap auto sign-in for
        # returning visitors who land logged-out (e.g. cookies were cleared).
        "auth_google_url": f"{APP_URL}/auth/google",
        "local_auth_enabled": LOCAL_AUTH_ENABLED,
    }

