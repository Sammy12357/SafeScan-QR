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
from .audit import role_for_email
from .auth import require_user_from_google_id
from .config import APP_URL
from .config import CLIENT_ID
from .config import LOCAL_AUTH_ENABLED
from .config import templates
from .request_helpers import request_ip

# =============================================================================
# USER ACCOUNTS, PASSWORDS & USERNAMES
# =============================================================================
def local_user_id(email):
    return "local_" + hashlib.sha256(email.strip().lower().encode()).hexdigest()[:16]

def canonical_user_id(email):
    return "user_" + hashlib.sha256(email.strip().lower().encode()).hexdigest()[:24]

def hash_password(password):
    salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260000)
    return salt.hex() + ":" + dk.hex()

def verify_password(password, stored):
    try:
        salt_hex, dk_hex = stored.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 260000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

def save_local_user(email, request=None):
    uid = canonical_user_id(email)
    return save_user_to_db(uid, email, request)

def email_account_exists(email):
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        return False
    with get_conn() as conn:
        existing_user = conn.execute("SELECT 1 FROM users WHERE lower(email) = ? LIMIT 1", (normalized_email,)).fetchone()
        existing_local = conn.execute("SELECT 1 FROM local_credentials WHERE lower(email) = ? LIMIT 1", (normalized_email,)).fetchone()
    return bool(existing_user or existing_local)

def duplicate_account_response(request, message="Email is already linked to an account. Please sign in instead."):
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": message,
            "tab": "register",
            "local_auth_enabled": LOCAL_AUTH_ENABLED,
            "google_client_id": CLIENT_ID or "",
            "auth_google_url": f"{APP_URL}/auth/google",
        },
        status_code=409,
    )

def username_required(user):
    return bool(user) and not (user.get("username") or "").strip()

def sanitize_username(username):
    cleaned = (username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", cleaned):
        raise SafeScanError("Username must be 3-24 characters and can only use letters, numbers, and underscores.", 400)
    return cleaned

def set_user_username(user_id, username):
    cleaned = sanitize_username(username)
    with get_conn() as conn:
        current = conn.execute("SELECT username FROM users WHERE google_id = ?", (user_id,)).fetchone()
        if current and (current[0] or "").strip():
            raise SafeScanError("Username is already set for this account.", 400)
        existing = conn.execute(
            "SELECT google_id FROM users WHERE lower(username) = lower(?) AND google_id != ?",
            (cleaned, user_id)
        ).fetchone()
        if existing:
            raise SafeScanError("That username is already taken.", 400)
        conn.execute("UPDATE users SET username = ? WHERE google_id = ?", (cleaned, user_id))
    return cleaned

def response_after_login(user_id, request, next_url=""):
    destination = safe_next_url(request, next_url)
    if destination == "/" and username_required(require_user_from_google_id(user_id)):
        destination = "/onboarding/username"
    return RedirectResponse(destination, status_code=303)

def safe_next_url(request: Request, raw="", fallback="/"):
    raw = raw or ""
    raw = (raw or "").strip()
    parsed = urlparse(raw)
    if raw.startswith("/") and not raw.startswith("//") and not parsed.scheme and not parsed.netloc:
        return raw
    return fallback

def save_user_to_db(google_id, email, request=None, display_name="", picture=""):
    normalized_email = email.strip().lower()
    normalized_display_name = (display_name or "").strip()[:120]
    normalized_picture = (picture or "").strip()[:500]
    role = role_for_email(normalized_email)
    referral_code = hashlib.sha256(f"{normalized_email}:{APP_URL}".encode("utf-8")).hexdigest()[:10]
    with get_conn() as conn:
        existing = conn.execute(
            """
            SELECT google_id
            FROM users
            WHERE lower(email) = ? AND status != 'deleted'
            ORDER BY CASE WHEN google_id = ? THEN 0 ELSE 1 END, created_at
            LIMIT 1
            """,
            (normalized_email, google_id),
        ).fetchone()
        resolved_google_id = existing["google_id"] if existing else google_id
        google_sub = google_id if not google_id.startswith("user_") and not google_id.startswith("local_") else None
        conn.execute("""
            INSERT INTO users (google_id, email, display_name, picture, last_login, role, status, last_login_at, login_ip, created_at, referral_code, google_sub)
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)
            ON CONFLICT(google_id) DO UPDATE SET
                email=excluded.email,
                display_name=COALESCE(NULLIF(users.display_name, ''), excluded.display_name),
                picture=COALESCE(NULLIF(users.picture, ''), excluded.picture),
                last_login=excluded.last_login,
                last_login_at=excluded.last_login_at,
                login_ip=excluded.login_ip,
                referral_code=COALESCE(users.referral_code, excluded.referral_code),
                google_sub=COALESCE(users.google_sub, excluded.google_sub),
                role=CASE
                    WHEN users.role IN ('owner', 'admin') THEN users.role
                    ELSE excluded.role
                END
        """, (resolved_google_id, normalized_email, normalized_display_name, normalized_picture, datetime.now().isoformat(), role, now_iso(), request_ip(request) if request else None, now_iso(), referral_code, google_sub))
    return resolved_google_id

