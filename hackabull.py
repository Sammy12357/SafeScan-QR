from __future__ import annotations
import requests
import json
import warnings
import io
import sqlite3
import hashlib
import hmac
import re
import asyncio
import base64
import ipaddress
import secrets
import socket
import time
import csv
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qsl
from datetime import datetime, timedelta
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

try:
    from prometheus_client import Counter, Gauge, Histogram, CONTENT_TYPE_LATEST, generate_latest
except ImportError:
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    def Counter(*args, **kwargs):
        return _NoopMetric()

    def Gauge(*args, **kwargs):
        return _NoopMetric()

    def Histogram(*args, **kwargs):
        return _NoopMetric()

    def generate_latest():
        return b"# prometheus-client is not installed\n"


class _NoopMetric:
    def labels(self, **kwargs):
        return self

    def inc(self, amount=1):
        return None

    def dec(self, amount=1):
        return None

    def observe(self, value):
        return None


def build_metric(factory, *args, **kwargs):
    try:
        return factory(*args, **kwargs)
    except ValueError as exc:
        if "Duplicated timeseries" in str(exc):
            return _NoopMetric()
        raise

warnings.filterwarnings("ignore", category=ImportWarning)
load_dotenv()

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain
import safescan_model_calibration as sm_calibration

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID") or os.getenv("googe_client_id")
AUTH0_DOMAIN = (os.getenv("AUTH0_DOMAIN") or "dev-vnllaqnkkegs4xni.us.auth0.com").strip().rstrip("/")
AUTH0_AUDIENCES = {audience.strip() for audience in (os.getenv("AUTH0_CLIENT_IDS") or os.getenv("AUTH0_CLIENT_ID") or "1XfWxWOtDtN18JCCztRehzcJ1jOSBBic").split(",") if audience.strip()}
AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}/"
_AUTH0_JWKS_CACHE = {"keys": None, "fetched_at": 0.0}
_AUTH0_JWKS_TTL_SECONDS = 60 * 60
api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or os.getenv("googe_api_key")
AIRDROP_ADMIN_SECRET = os.getenv("AIRDROP_ADMIN_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "safescanqr@gmail.com")
ADMIN_EMAIL_GMAIL_COMPOSE_URL = f"https://mail.google.com/mail/?view=cm&fs=1&to={quote(ADMIN_EMAIL)}"
DEFAULT_ADMIN_EMAILS = {"homzajoe@gmail.com", "restreposamuel2004@gmail.com"}
ADMIN_ACCESS_DENYLIST = {email.strip().lower() for email in os.getenv("ADMIN_ACCESS_DENYLIST", "safescanqr@gmail.com").split(",") if email.strip()}
ADMIN_EMAILS = (
    DEFAULT_ADMIN_EMAILS
    | {email.strip().lower() for email in os.getenv("ADMIN_EMAILS", ADMIN_EMAIL).split(",") if email.strip()}
) - ADMIN_ACCESS_DENYLIST
OWNER_EMAILS = (
    {email.strip().lower() for email in os.getenv("OWNER_EMAILS", "").split(",") if email.strip()}
    or {ADMIN_EMAIL.strip().lower()}
) - ADMIN_ACCESS_DENYLIST
APP_URL = os.getenv("APP_URL", "https://safescan-qr.onrender.com").rstrip("/")
APP_ORIGIN = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(APP_URL)) if urlparse(APP_URL).scheme and urlparse(APP_URL).netloc else APP_URL
ALLOWED_ORIGINS = sorted({
    APP_ORIGIN,
    *(origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "https://safescan-qr.onrender.com",
    ).split(",")
    if origin.strip())
})
SESSION_COOKIE_NAME = "__Host-safescan_session"
SESSION_TTL_SECONDS = 24 * 60 * 60
SESSION_IDLE_SECONDS = 7 * 24 * 60 * 60
REMEMBER_ME_COOKIE_NAME = "__Host-safescan_remember"
REMEMBER_ME_TTL_DAYS = int(os.getenv("REMEMBER_ME_TTL_DAYS", "30"))
REMEMBER_ME_TTL_SECONDS = REMEMBER_ME_TTL_DAYS * 24 * 60 * 60
MAX_QR_UPLOAD_BYTES = int(os.getenv("MAX_QR_UPLOAD_BYTES", str(8 * 1024 * 1024)))
MAX_QR_PDF_PAGES = int(os.getenv("MAX_QR_PDF_PAGES", "5"))
VALID_ROLES = ("user", "admin", "owner")
VALID_STATUSES = ("active", "suspended", "deleted")
RATE_LIMITS = {}
AIRDROP_BASE_ALLOCATION = int(os.getenv("SQR_BASE_ALLOCATION", "100"))
AIRDROP_TOKEN_ALLOCATIONS = {
    "Scanner": AIRDROP_BASE_ALLOCATION,
    "Referrer": AIRDROP_BASE_ALLOCATION * 2,
    "Guardian": AIRDROP_BASE_ALLOCATION * 5,
}
LEGAL_VERSION = "v1.0"
LEGAL_LAST_UPDATED = "May 2026"
safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
SOLANA_RPC_URL = os.getenv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com")
ALPHA_STRIPE_PAYMENT_LINK = os.getenv("ALPHA_STRIPE_PAYMENT_LINK", "https://buy.stripe.com/00w3cxfdAb7OcKB4sC87K01").strip()
ALPHA_SOLANA_RECIPIENT = os.getenv("ALPHA_SOLANA_RECIPIENT", "").strip()
ALPHA_SOLANA_AMOUNT_SOL = os.getenv("ALPHA_SOLANA_AMOUNT_SOL", "").strip()
ALPHA_SOLANA_LABEL = os.getenv("ALPHA_SOLANA_LABEL", "SafeScan QR Alpha").strip()
ALPHA_SOLANA_MESSAGE = os.getenv("ALPHA_SOLANA_MESSAGE", "Alpha access to SafeScan QR premium API docs and endpoints.").strip()
MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() in ("1", "true", "yes", "on")
ML_MODEL_ENABLED = os.getenv("SAFESCAN_ML2_ENABLED", "true").lower() in ("1", "true", "yes", "on")
ML_MODEL_PATH = os.getenv("SAFESCAN_ML2_MODEL_PATH", os.path.join(os.path.dirname(__file__), "models", "final_model.keras"))
os.environ["SAFESCAN_ML2_MODEL_PATH"] = ML_MODEL_PATH
ML_MODEL_OBJECT_KEY = os.getenv("ML2_MODEL_OBJECT_KEY", "models/final_model.keras")
# How much the ML classifier(s) influence the final risk score, vs the
# deterministic rule-based score. Default 0.50 = even 50/50 split between
# the rule signals and the average ML score. The website ships a different
# (more reliable) ML model than the early URL classifier that prompted the
# original cap, so the model gets equal sway here. Override with
# SAFESCAN_ML_WEIGHT (0.0 disables ML influence entirely; clamped to 0.7
# so a runaway model still can't single-handedly dictate the verdict).
ML_AGGREGATE_WEIGHT = max(0.0, min(0.7, float(os.getenv("SAFESCAN_ML_WEIGHT", "0.50"))))
# Hide the per-ML-model row from the user-visible signals list. The ML data
# still lives in the response's `mlRisk` field for backend logging / audit,
# but we don't expose model field names ("url_classifier.joblib") in the
# user-facing UI. Flip to "true" if you need ML row visible for debugging.
ML_SIGNAL_VISIBLE = os.getenv("SAFESCAN_ML_SIGNAL_VISIBLE", "false").lower() in ("1", "true", "yes", "on")
LOCAL_AUTH_ENABLED = MOCK_MODE or APP_URL.startswith("http://127.0.0.1") or APP_URL.startswith("http://localhost")
APP_STARTED_AT = datetime.utcnow()
REQUEST_COUNT = build_metric(Counter, "safescan_requests_total", "Total HTTP requests", ["method", "path", "status"])
REQUEST_LATENCY = build_metric(
    Histogram,
    "safescan_request_duration_seconds",
    "HTTP request latency in seconds",
    ["path"],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0],
)
ACTIVE_SCANS = build_metric(Gauge, "safescan_active_scans", "In-flight scan requests")
QR_UPLOADS = build_metric(Counter, "safescan_qr_uploads_total", "Stored QR upload artifacts", ["backend"])
HIGH_RISK_TLDS = {".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf"}
URL_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MALICIOUS_CONTRACT_BLOCKLIST = {
    "11111111111111111111111111111111",
    "drainwallet111111111111111111111111111111",
}

templates = Jinja2Templates(directory="templates")
_template_response = templates.TemplateResponse


def format_time_only(value):
    if value in (None, ""):
        return ""
    raw = str(value).strip()
    if not raw:
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return parsed.strftime("%H:%M:%S")
    except ValueError:
        match = re.search(r"T(\d{2}:\d{2}:\d{2})", raw) or re.search(r"\b(\d{2}:\d{2}:\d{2})\b", raw)
        return match.group(1) if match else raw


templates.env.filters["time_only"] = format_time_only


def template_response_compat(*args, **kwargs):
    if args and isinstance(args[0], str):
        name = args[0]
        context = args[1] if len(args) > 1 else kwargs.pop("context", {})
        request = context.get("request") if isinstance(context, dict) else None
        if request is None:
            raise RuntimeError("TemplateResponse context must include request.")
        return _template_response(request, name, context, *args[2:], **kwargs)
    return _template_response(*args, **kwargs)


templates.TemplateResponse = template_response_compat
_IMAGE_LIBS = None

def image_libs():
    global _IMAGE_LIBS
    if _IMAGE_LIBS is None:
        from PIL import Image, ImageEnhance, ImageFilter, ImageOps
        from pyzbar.pyzbar import decode
        _IMAGE_LIBS = (Image, ImageEnhance, ImageFilter, ImageOps, decode)
    return _IMAGE_LIBS

def init_db():
    conn = sqlite3.connect(database_path())
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_results (url TEXT PRIMARY KEY, status TEXT, timestamp TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        google_id TEXT PRIMARY KEY,
                        email TEXT,
                        last_login TEXT,
                        role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin', 'owner')),
                        status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted')),
                        last_login_at TEXT,
                        login_ip TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        deleted_at TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans (email TEXT PRIMARY KEY, url_found TEXT, scan_count INTEGER DEFAULT 0, wallet_address TEXT, tokens_sent INTEGER DEFAULT 0)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_events
                        (email TEXT NOT NULL, payload_hash TEXT NOT NULL, url_found TEXT NOT NULL,
                         first_scanned_at TEXT NOT NULL, user_id TEXT,
                         PRIMARY KEY (email, payload_hash))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS consent_logs
                        (id TEXT PRIMARY KEY, user_id TEXT, ip_hash TEXT NOT NULL,
                         consent_given INTEGER NOT NULL, consent_type TEXT NOT NULL,
                         banner_version TEXT NOT NULL, timestamp TEXT NOT NULL,
                         user_agent TEXT, locale TEXT, expiry_date TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS data_requests
                        (id TEXT PRIMARY KEY, email TEXT NOT NULL, region TEXT,
                         request_type TEXT NOT NULL, details TEXT, status TEXT NOT NULL,
                         submitted_at TEXT NOT NULL, completed_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS breach_reports
                        (id TEXT PRIMARY KEY, discovery_date TEXT NOT NULL,
                         data_categories TEXT NOT NULL, users_affected TEXT NOT NULL,
                         likely_consequences TEXT NOT NULL, measures_taken TEXT NOT NULL,
                         created_at TEXT NOT NULL, template TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS age_confirmations
                        (email TEXT PRIMARY KEY, threshold INTEGER NOT NULL,
                         locale TEXT, confirmed_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS privacy_opt_outs
                        (id TEXT PRIMARY KEY, email TEXT NOT NULL, region TEXT,
                         opt_out_type TEXT NOT NULL, timestamp TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS waitlist_signups
                        (email TEXT PRIMARY KEY, source TEXT, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions
                        (id TEXT PRIMARY KEY, google_id TEXT NOT NULL,
                         created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                         last_active TEXT NOT NULL, revoked_at TEXT,
                         ip_hash TEXT, user_agent TEXT,
                         FOREIGN KEY(google_id) REFERENCES users(google_id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS persistent_sessions
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                         token_hash TEXT NOT NULL UNIQUE,
                         created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                         last_used TEXT, revoked_at TEXT,
                         ip_hash TEXT, user_agent TEXT,
                         FOREIGN KEY(user_id) REFERENCES users(google_id))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs
                        (id TEXT PRIMARY KEY, actor_user_id TEXT, action TEXT NOT NULL,
                         target_type TEXT, target_id TEXT, metadata TEXT,
                         ip_address TEXT, user_agent TEXT, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS abuse_flags
                        (id TEXT PRIMARY KEY, email TEXT, flag_type TEXT NOT NULL,
                         detail TEXT NOT NULL, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_history
                        (id TEXT PRIMARY KEY, email TEXT NOT NULL, url TEXT NOT NULL,
                         risk_score INTEGER, verdict TEXT, signals TEXT,
                         reported INTEGER DEFAULT 0, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS upload_artifacts
                        (id TEXT PRIMARY KEY, user_id TEXT, email TEXT,
                         object_key TEXT NOT NULL, backend TEXT NOT NULL,
                         content_type TEXT, byte_size INTEGER NOT NULL,
                         sha256 TEXT NOT NULL, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS url_reports
                        (id TEXT PRIMARY KEY, url TEXT NOT NULL, reporter_email TEXT,
                         reason TEXT NOT NULL, risk_score INTEGER, status TEXT NOT NULL DEFAULT 'pending',
                         created_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS url_blocklist
                        (id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, reason TEXT,
                         added_by TEXT, created_at TEXT NOT NULL, removed_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS ip_registry
                        (id TEXT PRIMARY KEY, ip_address TEXT NOT NULL, user_id TEXT NOT NULL,
                         event_type TEXT NOT NULL, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_velocity
                        (user_id TEXT PRIMARY KEY, scans_last_hour INTEGER DEFAULT 0,
                         scans_last_day INTEGER DEFAULT 0, last_scan_at TEXT,
                         last_scan_url TEXT, duplicate_count INTEGER DEFAULT 0,
                         fast_scan_count INTEGER DEFAULT 0, updated_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS fraud_flags
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, check_name TEXT NOT NULL,
                         severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
                         reason TEXT NOT NULL, metadata TEXT, auto_disqualify INTEGER DEFAULT 0,
                         reviewed INTEGER DEFAULT 0, reviewed_by TEXT, reviewed_at TEXT,
                         review_outcome TEXT CHECK(review_outcome IN ('cleared','disqualified','escalated') OR review_outcome IS NULL),
                         created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS device_fingerprints
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                         first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                         UNIQUE(user_id, fingerprint))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS api_keys
                        (id TEXT PRIMARY KEY, name TEXT NOT NULL, key_hint TEXT NOT NULL,
                         key_hash TEXT NOT NULL, scopes TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
                         created_by TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT,
                         last_used_at TEXT, revoked_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS referrals
                        (id TEXT PRIMARY KEY, referrer_email TEXT NOT NULL, referred_email TEXT NOT NULL,
                         counted INTEGER DEFAULT 0, created_at TEXT NOT NULL,
                         UNIQUE(referred_email))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS wallets
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE,
                         address TEXT NOT NULL UNIQUE, verified INTEGER NOT NULL DEFAULT 1,
                         connected_at TEXT NOT NULL, sol_balance REAL, tx_count INTEGER,
                         wallet_age_days INTEGER, onchain_verified_at TEXT,
                         disconnected_at TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS wallet_nonces
                        (user_id TEXT PRIMARY KEY, wallet_address TEXT NOT NULL,
                         nonce TEXT NOT NULL, message TEXT NOT NULL,
                         issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                         used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS alpha_subscriptions
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                         email TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'alpha_premium',
                         provider TEXT NOT NULL DEFAULT 'stripe',
                         status TEXT NOT NULL DEFAULT 'active',
                         purchased_at TEXT NOT NULL,
                         checkout_session_id TEXT, stripe_payment_link TEXT,
                         client_reference_id TEXT, metadata TEXT,
                         created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                         UNIQUE(user_id, tier, provider))''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS go_ghost_removal_jobs
                        (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, email TEXT NOT NULL,
                         broker TEXT NOT NULL, status TEXT NOT NULL, detail TEXT,
                         target_url TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_google_id ON sessions(google_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_persistent_sessions_token_hash ON persistent_sessions(token_hash)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_persistent_sessions_user_id ON persistent_sessions(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_abuse_email ON abuse_flags(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_email ON scan_history(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_created ON scan_history(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_upload_artifacts_user_id ON upload_artifacts(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_status ON url_reports(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocklist_url ON url_blocklist(url)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_registry_ip ON ip_registry(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_ip_registry_user ON ip_registry(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_user ON fraud_flags(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_fraud_reviewed ON fraud_flags(reviewed)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_fingerprint ON device_fingerprints(fingerprint)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallets_address ON wallets(address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_wallet_nonces_wallet ON wallet_nonces(wallet_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alpha_subscriptions_email ON alpha_subscriptions(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alpha_subscriptions_purchased ON alpha_subscriptions(purchased_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_go_ghost_jobs_user ON go_ghost_removal_jobs(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_go_ghost_jobs_broker ON go_ghost_removal_jobs(broker)")
    cursor.execute("PRAGMA table_info(users)")
    user_columns = {row[1] for row in cursor.fetchall()}
    user_migrations = {
        "role": "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin', 'owner'))",
        "status": "ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted'))",
        "last_login_at": "ALTER TABLE users ADD COLUMN last_login_at TEXT",
        "login_ip": "ALTER TABLE users ADD COLUMN login_ip TEXT",
        "created_at": "ALTER TABLE users ADD COLUMN created_at TEXT",
        "deleted_at": "ALTER TABLE users ADD COLUMN deleted_at TEXT",
        "airdrop_status": "ALTER TABLE users ADD COLUMN airdrop_status TEXT NOT NULL DEFAULT 'eligible' CHECK(airdrop_status IN ('eligible','flagged','disqualified','cleared'))",
        "fraud_score": "ALTER TABLE users ADD COLUMN fraud_score INTEGER DEFAULT 0",
        "display_name": "ALTER TABLE users ADD COLUMN display_name TEXT",
        "picture": "ALTER TABLE users ADD COLUMN picture TEXT",
        "referral_code": "ALTER TABLE users ADD COLUMN referral_code TEXT",
    }
    for column, ddl in user_migrations.items():
        if column not in user_columns:
            cursor.execute(ddl)
    if "google_sub" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
    if "username" not in user_columns:
        cursor.execute("ALTER TABLE users ADD COLUMN username TEXT")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub)")
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users(lower(username)) WHERE username IS NOT NULL AND username != ''")
    if ADMIN_ACCESS_DENYLIST:
        placeholders = ",".join("?" for _ in ADMIN_ACCESS_DENYLIST)
        cursor.execute(
            f"UPDATE users SET role = 'user' WHERE lower(email) IN ({placeholders}) AND role IN ('admin', 'owner')",
            tuple(sorted(ADMIN_ACCESS_DENYLIST))
        )
    if ADMIN_EMAILS:
        placeholders = ",".join("?" for _ in ADMIN_EMAILS)
        cursor.execute(
            f"UPDATE users SET role = 'admin' WHERE lower(email) IN ({placeholders}) AND role != 'owner'",
            tuple(sorted(ADMIN_EMAILS))
        )
    if OWNER_EMAILS:
        placeholders = ",".join("?" for _ in OWNER_EMAILS)
        cursor.execute(
            f"UPDATE users SET role = 'owner' WHERE lower(email) IN ({placeholders})",
            tuple(sorted(OWNER_EMAILS))
        )
    cursor.execute("UPDATE users SET created_at = COALESCE(created_at, last_login, ?)", (datetime.utcnow().isoformat() + "Z",))
    cursor.execute("PRAGMA table_info(scans)")
    scan_columns = {row[1] for row in cursor.fetchall()}
    if "airdrop_eligible" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_eligible INTEGER DEFAULT 0")
    if "airdrop_tokens_sent" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_tokens_sent INTEGER DEFAULT 0")
    if "airdrop_sent_at" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN airdrop_sent_at TEXT")
    if "user_id" not in scan_columns:
        cursor.execute("ALTER TABLE scans ADD COLUMN user_id TEXT")
    cursor.execute("UPDATE scans SET airdrop_eligible = 1 WHERE scan_count >= 5")
    cursor.execute("PRAGMA table_info(scan_history)")
    scan_history_columns = {row[1] for row in cursor.fetchall()}
    if "user_id" not in scan_history_columns:
        cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id TEXT")
    cursor.execute("PRAGMA table_info(scan_events)")
    scan_event_columns = {row[1] for row in cursor.fetchall()}
    if "user_id" not in scan_event_columns:
        cursor.execute("ALTER TABLE scan_events ADD COLUMN user_id TEXT")
    cursor.execute("""
        UPDATE scan_history
        SET user_id = (
            SELECT users.google_id
            FROM users
            WHERE lower(users.email) = lower(scan_history.email)
            LIMIT 1
        )
        WHERE user_id IS NULL
    """)
    cursor.execute("""
        UPDATE scans
        SET user_id = (
            SELECT users.google_id
            FROM users
            WHERE lower(users.email) = lower(scans.email)
            LIMIT 1
        )
        WHERE user_id IS NULL
    """)
    cursor.execute("""
        UPDATE scan_events
        SET user_id = (
            SELECT users.google_id
            FROM users
            WHERE lower(users.email) = lower(scan_events.email)
            LIMIT 1
        )
        WHERE user_id IS NULL
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_history_user_id ON scan_history(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_user_id ON scan_events(user_id)")
    cursor.execute('''CREATE TABLE IF NOT EXISTS local_credentials
                        (email TEXT PRIMARY KEY,
                         password_hash TEXT NOT NULL,
                         created_at TEXT NOT NULL,
                         user_id TEXT)''')
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_local_credentials_email_lower ON local_credentials(lower(email))")
    conn.commit()
    conn.close()

init_db()

def db_connect():
    return get_conn()

class SafeScanError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def role_for_email(email):
    normalized = (email or "").strip().lower()
    if normalized in OWNER_EMAILS:
        return "owner"
    if normalized in ADMIN_EMAILS:
        return "admin"
    return "user"

def sanitize_metadata(value):
    blocked = ("password", "token", "secret", "key", "hash", "credential")
    if isinstance(value, dict):
        return {
            key: sanitize_metadata(item)
            for key, item in value.items()
            if not any(term in str(key).lower() for term in blocked)
        }
    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value]
    return value

def audit_log(action, request=None, actor_user_id=None, target_type=None, target_id=None, metadata=None):
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    make_id("audit"),
                    actor_user_id,
                    action,
                    target_type,
                    target_id,
                    json.dumps(sanitize_metadata(metadata or {})),
                    request_ip(request) if request else None,
                    request.headers.get("user-agent", "") if request else None,
                    now_iso(),
                )
            )
    except sqlite3.Error:
        pass

_COOKIE_SECURE = not LOCAL_AUTH_ENABLED
_COOKIE_SAMESITE = "strict" if _COOKIE_SECURE else "lax"

def set_session_cookie(response, session_id):
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )

def clear_session_cookie(response):
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=True,
        samesite="strict",
    )

def wants_remember_me(value):
    if value is None:
        return True
    return str(value).strip().lower() not in ("0", "false", "off", "no")

def remember_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def set_remember_me_cookie(response, token):
    response.set_cookie(
        REMEMBER_ME_COOKIE_NAME,
        token,
        max_age=REMEMBER_ME_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )

def clear_remember_me_cookie(response):
    response.delete_cookie(
        REMEMBER_ME_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=True,
        samesite="strict",
    )

def create_remember_me_token(user_id, request):
    raw_token = secrets.token_urlsafe(48)
    created = datetime.utcnow()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO persistent_sessions
                (id, user_id, token_hash, created_at, expires_at, last_used, revoked_at, ip_hash, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                make_id("remember"),
                user_id,
                remember_token_hash(raw_token),
                created.isoformat() + "Z",
                (created + timedelta(seconds=REMEMBER_ME_TTL_SECONDS)).isoformat() + "Z",
                created.isoformat() + "Z",
                None,
                hash_ip(request_ip(request)),
                request.headers.get("user-agent", ""),
            ),
        )
    return raw_token

def issue_remember_me_cookie(response, user_id, request):
    set_remember_me_cookie(response, create_remember_me_token(user_id, request))

def validate_and_rotate_remember_me(request):
    raw_token = request.cookies.get(REMEMBER_ME_COOKIE_NAME)
    if not raw_token:
        return None, None
    token_hash = remember_token_hash(raw_token)
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT ps.id AS persistent_session_id, ps.expires_at, ps.revoked_at,
                   u.google_id, u.email, u.username, u.display_name, u.picture,
                   u.role, u.status, u.last_login_at, u.login_ip, u.google_sub
            FROM persistent_sessions ps
            JOIN users u ON u.google_id = ps.user_id
            WHERE ps.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if not row:
            return None, None
        try:
            expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", ""))
        except ValueError:
            conn.execute("UPDATE persistent_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), row["persistent_session_id"]))
            return None, None
        if row["revoked_at"] or expires_at < datetime.utcnow() or row["status"] != "active":
            conn.execute("UPDATE persistent_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), row["persistent_session_id"]))
            return None, None

        new_token = secrets.token_urlsafe(48)
        now = datetime.utcnow()
        conn.execute(
            "UPDATE persistent_sessions SET last_used = ?, revoked_at = ? WHERE id = ?",
            (now.isoformat() + "Z", now.isoformat() + "Z", row["persistent_session_id"]),
        )
        conn.execute(
            """
            INSERT INTO persistent_sessions
                (id, user_id, token_hash, created_at, expires_at, last_used, revoked_at, ip_hash, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                make_id("remember"),
                row["google_id"],
                remember_token_hash(new_token),
                now.isoformat() + "Z",
                (now + timedelta(seconds=REMEMBER_ME_TTL_SECONDS)).isoformat() + "Z",
                now.isoformat() + "Z",
                None,
                hash_ip(request_ip(request)),
                request.headers.get("user-agent", ""),
            ),
        )
        user = dict(row)
        user.pop("persistent_session_id", None)
        user.pop("expires_at", None)
        user.pop("revoked_at", None)
        return user, new_token

def revoke_all_remember_me(user_id):
    if not user_id:
        return
    with get_conn() as conn:
        conn.execute(
            "UPDATE persistent_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ?",
            (now_iso(), user_id),
        )

def cleanup_persistent_sessions():
    cutoff = now_iso()
    with get_conn() as conn:
        conn.execute("DELETE FROM persistent_sessions WHERE expires_at < ?", (cutoff,))

def _b64url_decode(value):
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)

def _decode_jwt_unverified(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT.")
    header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    return header, payload, parts

def _fetch_auth0_jwks():
    cached_keys = _AUTH0_JWKS_CACHE.get("keys")
    if cached_keys and (time.time() - _AUTH0_JWKS_CACHE["fetched_at"]) < _AUTH0_JWKS_TTL_SECONDS:
        return cached_keys
    response = requests.get(f"{AUTH0_ISSUER}.well-known/jwks.json", timeout=5)
    response.raise_for_status()
    keys = response.json().get("keys") or []
    _AUTH0_JWKS_CACHE["keys"] = keys
    _AUTH0_JWKS_CACHE["fetched_at"] = time.time()
    return keys

def _rsa_public_key_from_jwk(jwk):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return RSAPublicNumbers(e, n).public_key()

def verify_auth0_id_token(token):
    """Validate an Auth0-signed RS256 idToken via tenant JWKS. Returns claims."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    header, payload, parts = _decode_jwt_unverified(token)
    if header.get("alg") != "RS256":
        raise ValueError("Unsupported JWT algorithm.")
    kid = header.get("kid")
    if not kid:
        raise ValueError("JWT missing kid.")
    jwks = _fetch_auth0_jwks()
    matching = next((key for key in jwks if key.get("kid") == kid), None)
    if not matching:
        # JWKS may have rotated; force refresh once.
        _AUTH0_JWKS_CACHE["fetched_at"] = 0.0
        jwks = _fetch_auth0_jwks()
        matching = next((key for key in jwks if key.get("kid") == kid), None)
    if not matching:
        raise ValueError("No matching Auth0 signing key.")
    public_key = _rsa_public_key_from_jwk(matching)
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    signature = _b64url_decode(parts[2])
    public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    issuer = payload.get("iss", "")
    if issuer.rstrip("/") != AUTH0_ISSUER.rstrip("/"):
        raise ValueError("JWT issuer mismatch.")
    audience = payload.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if AUTH0_AUDIENCES and not any(aud in AUTH0_AUDIENCES for aud in audiences if aud):
        raise ValueError("JWT audience mismatch.")
    now = int(time.time())
    if int(payload.get("exp", 0)) < now:
        raise ValueError("JWT expired.")
    if not payload.get("email"):
        raise ValueError("JWT missing email claim.")
    return payload

def request_session_id(request):
    auth_header = request.headers.get("authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return request.cookies.get(SESSION_COOKIE_NAME)

def create_session(google_id, request):
    session_id = secrets.token_urlsafe(32)
    created = datetime.utcnow()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                google_id,
                created.isoformat() + "Z",
                (created + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat() + "Z",
                created.isoformat() + "Z",
                None,
                hash_ip(request_ip(request)),
                request.headers.get("user-agent", ""),
            )
        )
    return session_id

def get_session_user(request):
    if getattr(request.state, "session_user_loaded", False):
        return getattr(request.state, "session_user", None)

    def cache_session_user(user):
        request.state.session_user_loaded = True
        request.state.session_user = user
        return user

    remembered_user = getattr(request.state, "remembered_user", None)
    if remembered_user and remembered_user.get("status") == "active":
        return cache_session_user(remembered_user)

    session_id = request_session_id(request)
    if not session_id:
        return cache_session_user(None)
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT s.id AS session_id, s.expires_at, s.last_active, s.revoked_at,
                   u.google_id, u.email, u.username, u.display_name, u.picture,
                   u.role, u.status, u.last_login_at, u.login_ip
            FROM sessions s
            JOIN users u ON u.google_id = s.google_id
            WHERE s.id = ?
            """,
            (session_id,)
        ).fetchone()
        if not row:
            return cache_session_user(None)
        try:
            expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", ""))
            last_active = datetime.fromisoformat(str(row["last_active"]).replace("Z", ""))
        except ValueError:
            return cache_session_user(None)
        if row["revoked_at"] or expires_at < datetime.utcnow() or datetime.utcnow() - last_active > timedelta(seconds=SESSION_IDLE_SECONDS):
            conn.execute("UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), session_id))
            return cache_session_user(None)
        if row["status"] != "active":
            return cache_session_user(None)
        conn.execute("UPDATE sessions SET last_active = ? WHERE id = ?", (now_iso(), session_id))
        return cache_session_user(dict(row))

def require_user(request):
    user = get_session_user(request)
    if not user:
        audit_log("auth.failed", request=request)
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user

def require_user_from_google_id(google_id):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT google_id, email, username, display_name, picture, role, status, google_sub FROM users WHERE google_id = ?", (google_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return dict(row)

def has_role(user, role):
    hierarchy = ["guest", "user", "admin", "owner"]
    return hierarchy.index(user.get("role", "guest")) >= hierarchy.index(role)

def require_role_user(request, role):
    user = require_user(request)
    if not has_role(user, role):
        audit_log("auth.permission_denied", request=request, actor_user_id=user.get("google_id"), metadata={"requiredRole": role})
        raise HTTPException(status_code=403, detail="You do not have permission to do this.")
    return user

def enforce_rate_limit(request, bucket, limit, window_seconds, user_key=None):
    identity = user_key or request_ip(request)
    key = f"{bucket}:{identity}"
    now = time.time()
    hits = [stamp for stamp in RATE_LIMITS.get(key, []) if now - stamp < window_seconds]
    if len(hits) >= limit:
        retry_after = max(1, int(window_seconds - (now - hits[0])))
        audit_log("auth.rate_limited", request=request, metadata={"bucket": bucket, "retryAfter": retry_after})
        return JSONResponse(
            {"error": "Too many requests", "retryAfter": retry_after},
            status_code=429,
            headers={"Retry-After": str(retry_after)}
        )
    hits.append(now)
    RATE_LIMITS[key] = hits
    return None

def validate_strict_payload(payload, allowed_fields):
    if not isinstance(payload, dict):
        raise SafeScanError("Invalid request.", 400)
    unexpected = set(payload.keys()) - set(allowed_fields)
    if unexpected:
        raise SafeScanError("Unexpected fields: " + ", ".join(sorted(unexpected)), 400)

def is_private_hostname(hostname):
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in ("localhost",) or host.endswith(".localhost") or "render-internal" in host:
        return True
    try:
        ip_values = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ip_values = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
        except socket.gaierror:
            return False
    return any(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast for ip in ip_values)

def validate_public_url(target_url):
    if not isinstance(target_url, str) or len(target_url.strip()) > 2048:
        raise SafeScanError("URL is required and must be 2048 characters or fewer.", 400)
    normalized = normalize_url(target_url)
    parsed = urlparse(normalized)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SafeScanError("Only valid http and https URLs are supported.", 400)
    if is_private_hostname(parsed.hostname):
        raise SafeScanError("Private, localhost, and internal service URLs are blocked.", 400)
    return normalized

def follow_safe_redirects(target_url, max_redirects=10):
    current = validate_public_url(target_url)
    chain = []
    session = requests.Session()
    for _ in range(max_redirects + 1):
        response = session.get(current, timeout=6, allow_redirects=False, stream=True)
        response.close()
        chain.append(response)
        if response.status_code not in (301, 302, 303, 307, 308):
            return chain
        location = response.headers.get("location")
        if not location:
            return chain
        current = validate_public_url(urljoin(current, location))
    raise requests.TooManyRedirects()

def flag_abuse(email, flag_type, detail):
    with get_conn() as conn:
        conn.execute("INSERT INTO abuse_flags VALUES (?, ?, ?, ?, ?)", (make_id("flag"), email, flag_type, detail, now_iso()))

def validate_wallet_address(address):
    clean = (address or "").strip()
    if not clean:
        return "", None
    if not is_valid_solana_address(clean):
        raise SafeScanError("Invalid Solana wallet address.", 400)
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT user_id FROM wallets WHERE address = ? AND verified = 1
            UNION
            SELECT email FROM scans WHERE wallet_address = ?
            LIMIT 1
            """,
            (clean, clean)
        ).fetchone()
    return clean, row[0] if row else None

def decode_base58(value):
    number = 0
    for char in value:
        number *= 58
        if char not in BASE58_ALPHABET:
            raise ValueError("Invalid base58 character")
        number += BASE58_ALPHABET.index(char)
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * leading_zeroes + encoded

def is_valid_solana_address(address):
    clean = (address or "").strip()
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", clean):
        return False
    try:
        return len(decode_base58(clean)) == 32
    except ValueError:
        return False

def wallet_verification_message(nonce, email, issued_at, expires_at):
    return "\n".join([
        "SafeScan QR - Wallet Verification",
        "",
        "Sign this message to connect your wallet.",
        "This request will not trigger a blockchain transaction",
        "or cost any fees.",
        "",
        f"Nonce: {nonce}",
        f"Account: {email}",
        f"Issued: {issued_at}",
        f"Expires: {expires_at}",
    ])

def cleanup_wallet_nonces():
    cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM wallet_nonces WHERE expires_at < ? OR (used = 1 AND created_at < ?)",
            (now_iso(), cutoff)
        )

def get_verified_wallet(user_id):
    with get_conn() as conn:
        rows = user_scoped_select(conn, "wallets", "verified = 1")
        row = next((item for item in rows if item["user_id"] == user_id), None)
        if not row and not rls_user_id():
            row = conn.execute(
                "SELECT * FROM wallets WHERE user_id = ? AND verified = 1",
                (user_id,)
            ).fetchone()
    return dict(row) if row else None

def verify_solana_signature(wallet_address, signature, message):
    public_key_bytes = decode_base58(wallet_address)
    signature_bytes = decode_base58(signature)
    if len(public_key_bytes) != 32 or len(signature_bytes) != 64:
        raise ValueError("Invalid signature or public key length")
    Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
        signature_bytes,
        message.encode("utf-8")
    )

async def verify_wallet_on_chain(wallet_address, user_id):
    try:
        public_key = wallet_address
        balance_payload = {
            "jsonrpc": "2.0",
            "id": "safescan-balance",
            "method": "getBalance",
            "params": [public_key, {"commitment": "confirmed"}],
        }
        sig_payload = {
            "jsonrpc": "2.0",
            "id": "safescan-signatures",
            "method": "getSignaturesForAddress",
            "params": [public_key, {"limit": 5}],
        }
        balance_response, sig_response = await asyncio.gather(
            asyncio.to_thread(requests.post, SOLANA_RPC_URL, json=balance_payload, timeout=8),
            asyncio.to_thread(requests.post, SOLANA_RPC_URL, json=sig_payload, timeout=8),
        )
        balance_lamports = ((balance_response.json().get("result") or {}).get("value") or 0)
        signatures = sig_response.json().get("result") or []
        tx_count = len(signatures)
        wallet_age_days = None
        oldest = signatures[-1] if signatures else None
        if oldest and oldest.get("blockTime"):
            wallet_age_days = int((time.time() - int(oldest["blockTime"])) // (24 * 60 * 60))
        with get_conn() as conn:
            conn.execute(
                """
                UPDATE wallets
                SET sol_balance = ?, tx_count = ?, wallet_age_days = ?, onchain_verified_at = ?
                WHERE address = ? AND user_id = ?
                """,
                (balance_lamports / 1_000_000_000, tx_count, wallet_age_days, now_iso(), wallet_address, user_id)
            )
        audit_log(
            "wallet.onchain_verified",
            actor_user_id=user_id,
            target_type="wallet",
            target_id=wallet_address[:8] + "...",
            metadata={"txCount": tx_count, "walletAgeDays": wallet_age_days}
        )
        if tx_count == 0 or (wallet_age_days is not None and wallet_age_days < 7):
            run_fraud_checks(
                "wallet_connect",
                user_id,
                None,
                {
                    "walletAddress": wallet_address,
                    "ip": "background_job",
                    "userAgent": "system",
                    "txCount": tx_count,
                    "walletAgeDays": wallet_age_days,
                }
            )
    except Exception as exc:
        print({"warning": "wallet_onchain_verification_failed", "error": str(exc)})

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

def save_scan_history(email, url, analysis, reported=False, user_id=None):
    normalized_email = (email or "").strip().lower()
    resolved_user_id = user_id or lookup_user_id_by_email(normalized_email)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                make_id("scan"),
                normalized_email,
                url[:2048],
                int(analysis.get("score") or analysis.get("confidenceScore") or 0),
                analysis.get("status") or status_from_risk(analysis.get("overallRisk")),
                json.dumps(analysis.get("reasons") or analysis.get("signals") or []),
                int(reported),
                now_iso(),
                resolved_user_id,
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
    with get_conn() as conn:
        scan_id = make_id("scan")
        conn.execute(
            "INSERT INTO scan_history (id, email, url, risk_score, verdict, signals, reported, created_at, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                resolved_email,
                url[:2048],
                int(analysis.get("score") or analysis.get("confidenceScore") or 0),
                analysis.get("status") or status_from_risk(analysis.get("overallRisk")),
                json.dumps(analysis.get("reasons") or analysis.get("signals") or []),
                int(reported),
                now_iso(),
                user_id,
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
        "profile_display_name": "Safe scanner",
        "profile_subtitle": username or display_name or email,
    }

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

def public_leaderboard_name(row):
    username = (row.get("username") or "").strip()
    if username:
        return username
    display_name = (row.get("display_name") or "").strip()
    if display_name:
        return display_name[:40]
    email = (row.get("email") or "").strip()
    if "@" in email:
        local, domain = email.split("@", 1)
        local_hint = local[:2] + "***" if len(local) > 2 else "***"
        return f"{local_hint}@{domain}"
    return "SafeScan user"

def get_global_leaderboard(limit=50):
    bounded_limit = max(1, min(int(limit or 50), 100))
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT
                u.google_id AS user_id,
                u.email,
                u.username,
                u.display_name,
                MAX(COALESCE(s.scan_count, 0), COALESCE(se.unique_events, 0), COALESCE(h.unique_saved_scans, 0)) AS scan_count,
                COALESCE(h.total_saved_scans, 0) AS total_saved_scans,
                COALESCE(h.last_history_at, se.last_event_at) AS last_scanned_at
            FROM users u
            LEFT JOIN scans s ON s.user_id = u.google_id OR lower(s.email) = lower(u.email)
            LEFT JOIN (
                SELECT user_id, lower(email) AS email_key, COUNT(*) AS total_saved_scans,
                       COUNT(DISTINCT url) AS unique_saved_scans, MAX(created_at) AS last_history_at
                FROM scan_history
                GROUP BY user_id, lower(email)
            ) h ON h.user_id = u.google_id OR h.email_key = lower(u.email)
            LEFT JOIN (
                SELECT lower(email) AS email_key, COUNT(DISTINCT payload_hash) AS unique_events, MAX(first_scanned_at) AS last_event_at
                FROM scan_events
                GROUP BY lower(email)
            ) se ON se.email_key = lower(u.email)
            WHERE u.status != 'deleted'
            GROUP BY u.google_id, u.email, u.username, u.display_name, s.scan_count, h.total_saved_scans, h.unique_saved_scans, h.last_history_at, se.unique_events, se.last_event_at
            ORDER BY scan_count DESC, total_saved_scans DESC, last_scanned_at DESC
            LIMIT ?
            """,
            (bounded_limit,)
        ).fetchall()
    leaders = []
    for index, row in enumerate(rows, start=1):
        item = dict(row)
        item["rank"] = index
        item["public_name"] = public_leaderboard_name(item)
        leaders.append(item)
    return leaders

def referral_code_for_user(email):
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        return ""
    with get_conn() as conn:
        row = conn.execute("SELECT referral_code FROM users WHERE email = ?", (normalized_email,)).fetchone()
        if row and row[0]:
            return row[0]
        code = hashlib.sha256(f"{normalized_email}:{APP_URL}".encode("utf-8")).hexdigest()[:10]
        conn.execute("UPDATE users SET referral_code = ? WHERE email = ?", (code, normalized_email))
        return code

def record_unique_scan(email, url, wallet, user_id=None):
    normalized_email = (email or "").strip().lower()
    resolved_user_id = user_id or lookup_user_id_by_email(normalized_email)
    normalized_payload = url.strip()[:2048]
    payload_hash = hashlib.sha256(normalized_payload.encode("utf-8")).hexdigest()
    cutoff = (datetime.utcnow() - timedelta(seconds=60)).isoformat()

    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (email, url_found, scan_count, wallet_address, user_id)
            VALUES (?, ?, 0, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                wallet_address = COALESCE(excluded.wallet_address, scans.wallet_address),
                user_id = COALESCE(scans.user_id, excluded.user_id)
        """, (normalized_email, normalized_payload, wallet, resolved_user_id))

        cursor.execute("SELECT url_found, scan_count FROM scans WHERE email = ?", (normalized_email,))
        previous_url, current_count = cursor.fetchone()

        cursor.execute("""
            INSERT OR IGNORE INTO scan_events (email, payload_hash, url_found, first_scanned_at, user_id)
            VALUES (?, ?, ?, ?, ?)
        """, (normalized_email, payload_hash, normalized_payload, datetime.now().isoformat(), resolved_user_id))

        if cursor.rowcount == 0:
            cursor.execute("SELECT first_scanned_at FROM scan_events WHERE email = ? AND payload_hash = ?", (normalized_email, payload_hash))
            existing = cursor.fetchone()
            if existing and str(existing[0]) >= cutoff:
                return False
            return False

        # Existing rows may already have counted the last scanned payload before
        # scan_events existed. Backfill that event without giving an extra scan.
        previous_urls = [entry.strip() for entry in str(previous_url or "").split(",") if entry.strip()]
        if normalized_payload in previous_urls and current_count > 0:
            cursor.execute("""
                UPDATE scans
                SET wallet_address = COALESCE(?, wallet_address),
                    user_id = COALESCE(user_id, ?)
                WHERE email = ?
            """, (wallet, resolved_user_id, normalized_email))
            return False

        previous_urls.append(normalized_payload)
        updated_urls = ",".join(previous_urls)

        cursor.execute("""
            UPDATE scans
            SET scan_count = scan_count + 1,
                url_found = ?,
                wallet_address = COALESCE(?, wallet_address),
                user_id = COALESCE(user_id, ?),
                airdrop_eligible = CASE WHEN scan_count + 1 >= 5 THEN 1 ELSE airdrop_eligible END
            WHERE email = ?
        """, (updated_urls, wallet, resolved_user_id, normalized_email))
        return True

def get_scan_count(email):
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT scan_count FROM scans WHERE email = ?", (email,))
        result = cursor.fetchone()
        return result[0] if result else 0

def get_cached_result(target_url: str):
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, timestamp FROM scan_results WHERE url = ?", (target_url,))
        row = cursor.fetchone()
    if row:
        last_scan = datetime.fromisoformat(row[1])
        if datetime.now() - last_scan < timedelta(hours=24):
            return row[0]
    return None

def save_to_cache(target_url: str, status: str):
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO scan_results VALUES (?, ?, ?)", (target_url, status, datetime.now().isoformat()))

def make_id(prefix):
    return f"{prefix}_{hashlib.sha256(f'{prefix}:{datetime.utcnow().isoformat()}:{os.urandom(8)}'.encode('utf-8')).hexdigest()[:24]}"

def hash_ip(ip_value):
    salt = os.getenv("PRIVACY_HASH_SALT", "safescan-dev-salt")
    return hashlib.sha256(f"{salt}:{ip_value or 'unknown'}".encode("utf-8")).hexdigest()

def request_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def locale_from_request(request: Request):
    return (request.headers.get("accept-language") or "en-US").split(",")[0].strip()

def is_eu_locale(locale):
    return locale.lower().split("-")[-1] in {
        "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr",
        "hu", "ie", "it", "lv", "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk",
        "si", "es", "se", "is", "li", "no"
    }

def is_california_locale_or_region(request: Request, region: str = ""):
    return region.lower() in ("ca", "california") or "california" in region.lower()

def admin_authorized(secret):
    return bool(AIRDROP_ADMIN_SECRET and secret == AIRDROP_ADMIN_SECRET)

def legal_context(request: Request, title, body_html):
    return {
        "request": request,
        "title": title,
        "body_html": body_html,
        "last_updated": LEGAL_LAST_UPDATED,
        "version": LEGAL_VERSION,
        "admin_email": ADMIN_EMAIL,
        "google_client_id": CLIENT_ID
    }

def get_user_export(email):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        scans = [dict(row) for row in conn.execute("SELECT * FROM scans WHERE email = ?", (email,))]
        events = [dict(row) for row in conn.execute("SELECT * FROM scan_events WHERE email = ?", (email,))]
        requests_ = [dict(row) for row in conn.execute("SELECT * FROM data_requests WHERE email = ?", (email,))]
        age = [dict(row) for row in conn.execute("SELECT * FROM age_confirmations WHERE email = ?", (email,))]
        opt_outs = [dict(row) for row in conn.execute("SELECT * FROM privacy_opt_outs WHERE email = ?", (email,))]
    return {"email": email, "scans": scans, "scanEvents": events, "dataRequests": requests_, "ageConfirmations": age, "privacyOptOuts": opt_outs}

def delete_user_data(email):
    with get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE email = ?", (email,))
        conn.execute("DELETE FROM scan_events WHERE email = ?", (email,))
        conn.execute("DELETE FROM users WHERE email = ?", (email,))
        conn.execute("DELETE FROM age_confirmations WHERE email = ?", (email,))

def risk_reason(label, severity, detail):
    return {"label": label, "severity": severity, "detail": detail}

def signal(check, result, severity, description, passed=True):
    return {
        "check": check,
        "label": check,
        "result": result,
        "severity": severity,
        "description": description,
        "detail": description,
        "passed": passed
    }

VIRUSTOTAL_ENGINE_ENTRIES = (
    "AbusixClean", "AcronisClean", "ADMINUSLabsClean", "AILabs (MONITORAPP)Clean",
    "AlienVaultClean", "Antiy-AVLClean", "BitDefenderClean", "BlockListClean",
    "BluelivClean", "CertegoClean", "ChainPatrolClean", "CINS ArmyClean", "CRDFClean",
    "Criminal IPClean", "CTX AIClean", "CybleClean", "CyRadarClean", "desenmascara.meClean",
    "DNS8Clean", "Dr.WebClean", "EmergingThreatsClean", "EmsisoftClean", "ESETClean",
    "ESTsecurityClean", "Forcepoint ThreatSeekerClean", "FortinetClean", "G-DataClean",
    "Google SafebrowsingClean", "GreenSnowClean", "Heimdal SecurityClean", "IPsumClean",
    "Juniper NetworksClean", "KasperskyClean", "LevelBlueClean", "LionicClean",
    "MalwaredClean", "MalwarePatrolClean", "OpenPhishClean", "Phishing DatabaseClean",
    "PhishtankClean", "PREBYTESClean", "Quick HealClean", "QutteraClean", "RisingClean",
    "SangforClean", "ScantitanClean", "SCUMWARE.orgClean", "SeclookupClean",
    "securolyticsClean", "SophosClean", "StopForumSpamClean", "Sucuri SiteCheckClean",
    "ThreatHiveClean", "URLhausClean", "Viettel Threat IntelligenceClean", "ViriBackClean",
    "VX VaultClean", "WebrootClean", "Yandex SafebrowsingClean", "ZeroCERTClean",
    "0xSI_f33dUnrated", "alphaMountain.aiUnrated", "AlphaSOCUnrated",
    "ArcSight Threat IntelligenceUnrated", "AutoShunUnrated", "Bfore.Ai PreCrimeUnrated",
    "BkavUnrated", "Chong Lua DaoUnrated", "Cluster25Unrated", "CSIS Security GroupUnrated",
    "CyanUnrated", "ErmesUnrated", "GCP Abuse IntelligenceUnrated", "GreyNoiseUnrated",
    "GridinsoftUnrated", "GuardpotUnrated", "Hunt.io IntelligenceUnrated", "K7AntiVirusUnrated",
    "LumuUnrated", "MalwareURLUnrated", "MimecastUnrated", "NetcraftUnrated", "PhishFortUnrated",
    "PhishLabsUnrated", "PrecisionSecUnrated", "SafeToOpenUnrated", "Sansec eComscanUnrated",
    "Snort IP sample listUnrated", "SOCRadarUnrated", "URLQueryUnrated", "VIPREUnrated",
    "Xcitium Verdict CloudUnrated", "ZeroFoxUnrated", "Artists Against 419Unrated",
    "benkow.ccUnrated", "CMC Threat IntelligenceUnrated",
)

def parse_virustotal_engine_entry(raw):
    for suffix, verdict in (("Malicious", "malicious"), ("Unrated", "unrated"), ("Clean", "clean")):
        if raw.endswith(suffix):
            return {"name": raw[:-len(suffix)], "verdict": verdict}
    return {"name": raw, "verdict": "unrated"}

VIRUSTOTAL_SEEDED_ENGINES = [parse_virustotal_engine_entry(entry) for entry in VIRUSTOTAL_ENGINE_ENTRIES]

def build_virustotal_summary(engines):
    clean = sum(1 for engine in engines if engine["verdict"] == "clean")
    unrated = sum(1 for engine in engines if engine["verdict"] == "unrated")
    malicious = sum(1 for engine in engines if engine["verdict"] == "malicious")
    return {"clean": clean, "unrated": unrated, "malicious": malicious, "total": len(engines)}

def virustotal_seed_result(target_url):
    engines = sorted(VIRUSTOTAL_SEEDED_ENGINES, key=lambda engine: engine["name"].lower())
    groups = {
        "clean": [engine for engine in engines if engine["verdict"] == "clean"],
        "unrated": [engine for engine in engines if engine["verdict"] == "unrated"],
        "malicious": [engine for engine in engines if engine["verdict"] == "malicious"],
    }
    return {
        "url": target_url,
        "scannedAt": now_iso(),
        "engines": engines,
        "groups": groups,
        "summary": build_virustotal_summary(engines),
        "provider": "VirusTotal",
        "mode": "seeded",
    }

def virustotal_breakdown_signal(vt_result):
    summary = vt_result["summary"]
    flagged = summary["malicious"]
    severity = "high" if flagged else "info"
    return signal(
        "VirusTotal Reputation",
        f"{flagged}/{summary['total']} engines flagged",
        severity,
        f"VirusTotal vendor breakdown: {summary['clean']} clean, {summary['unrated']} unrated, {summary['malicious']} malicious.",
        flagged == 0
    )

def score_from_signals(signals):
    high_count = sum(1 for item in signals if item["severity"] == "high")
    medium_count = sum(1 for item in signals if item["severity"] == "medium")
    low_count = sum(1 for item in signals if item["severity"] == "low")
    score = min(80, high_count * 40) + medium_count * 15 + low_count * 5
    if high_count >= 2 and medium_count >= 1:
        score = max(score, 90)
    elif high_count == 1 and medium_count >= 2:
        score = max(score, 75)
    return min(score, 100)

def risk_from_score(score):
    if score >= 80:
        return "high"
    if score >= 35:
        return "suspicious"
    return "safe"

def status_from_risk(overall_risk):
    return {"high": "MALICIOUS", "suspicious": "CAUTION", "safe": "SAFE"}.get(overall_risk, "CAUTION")

def severity_rank(item):
    return {"high": 0, "medium": 1, "low": 2}.get(item.get("severity"), 3)

def clamp_score(score):
    return max(0, min(100, int(round(float(score or 0)))))

def qr_image_from_payload(payload):
    import qrcode
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=2, box_size=4)
    qr.add_data(payload)
    qr.make(fit=True)
    return qr.make_image(fill_color="black", back_color="white").convert("RGB")

def classify_qr_with_ml(payload, image=None, input_source="generated_qr"):
    """Hybrid ML classification with calibration, cache, and feature bonus.

    Routes the decoded URL through the char-ngram URL classifier first
    (notebook reported 99% accuracy, F1-optimal threshold = 0.32). Falls
    back to the EfficientNet CNN only when the URL classifier artifact
    isn't deployed. Wraps the raw classifier output with:
      - SQLite-backed prediction cache keyed on URL (1hr TTL by default)
      - Calibrated decision bands (benign / uncertain / suspicious / mal)
      - Hand-crafted lexical bonus the char-ngram model can't see
      - Uncertain-band suppression: signal is hidden when probability
        lands in [UNCERTAIN_LOWER, UNCERTAIN_UPPER] so it can't pollute
        the score blend with low-confidence noise.

    See safescan_model_calibration.py for tuning knobs.
    """
    if not ML_MODEL_ENABLED:
        return {"enabled": False, "reason": "disabled"}

    # Cache hit short-circuits the entire ML stack and any image rendering.
    cached = sm_calibration.cache_get(payload) if payload else None
    if cached is not None:
        cached["cacheHit"] = True
        return cached

    generated_image = None
    try:
        ensure_ml_model_available()
        import ml_model_final as _ml_mod

        result = _ml_mod.predict_url(payload) if payload else None
        if result is not None:
            source_input = "decoded_url"
            model_name = os.path.basename(os.getenv(
                "SAFESCAN_URL_CLASSIFIER_PATH",
                os.path.join(os.path.dirname(__file__), "models", "url_classifier.joblib"),
            ))
        else:
            # CNN fallback - canonical rendering of the decoded URL so the
            # score depends on the URL, not on how the QR was photographed.
            generated_image = qr_image_from_payload(payload)
            result = _ml_mod.predict_image(generated_image)
            source_input = "generated_qr"
            model_name = os.path.basename(ML_MODEL_PATH)

        raw_mal_prob = float(result["malicious_prob"]) / 100.0
        bonus, bonus_reasons = sm_calibration.lexical_feature_bonus(payload)
        adjusted_prob = max(0.0, min(1.0, raw_mal_prob + bonus))
        decision = sm_calibration.interpret_probability(adjusted_prob)

        payload_obj = {
            "enabled": True,
            "trustSignal": decision.trust_signal,
            "model": model_name,
            "source": result.get("source"),
            "inputSource": source_input,
            "score": round(adjusted_prob * 100.0, 1),
            "label": decision.label,
            "bucket": decision.bucket,
            "severity": decision.severity,
            "benignProbability": round(1.0 - adjusted_prob, 4),
            "maliciousProbability": round(adjusted_prob, 4),
            "rawMaliciousProbability": round(raw_mal_prob, 4),
            "lexicalBonus": round(bonus, 4),
            "lexicalReasons": bonus_reasons,
            "raw": [round(1.0 - adjusted_prob, 6), round(adjusted_prob, 6)],
            "cacheHit": False,
        }
        if payload:
            sm_calibration.cache_put(payload, payload_obj)
        return payload_obj
    except Exception as exc:
        return {"enabled": False, "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        if generated_image is not None:
            generated_image.close()

def ml_signal_from_result(ml_result, label="ML Risk Model", description_prefix="CNN QR classifier"):
    if not ml_result or not ml_result.get("enabled"):
        return None
    # Suppress the ML signal entirely when calibration marked it uncertain;
    # forcing a binary call on a ~50/50 score only pollutes the score blend.
    if ml_result.get("trustSignal") is False:
        return None
    score_raw = float(ml_result["score"])
    severity = ml_result.get("severity") or (
        "high" if score_raw >= 80 else ("medium" if score_raw >= 40 else "low")
    )
    mal_pct = round(ml_result["maliciousProbability"] * 100, 1)
    safe_pct = round(ml_result["benignProbability"] * 100, 1)
    description = f"{description_prefix}: {safe_pct}% safe, {mal_pct}% malicious."
    reasons = ml_result.get("lexicalReasons") or []
    if reasons:
        description += f" Lexical bonus applied: {', '.join(reasons[:3])}."
    bucket = ml_result.get("bucket")
    passed = bucket == "benign" if bucket else score_raw < 40
    model_signal = signal(label, f"{round(score_raw, 1)}/100 ML probability", severity, description, passed)
    model_signal["distribution"] = {
        "benign": ml_result["benignProbability"],
        "malicious": ml_result["maliciousProbability"]
    }
    model_signal["model"] = ml_result.get("model")
    model_signal["bucket"] = bucket
    return model_signal

def blend_ml_score(rule_score, ml_results, signals):
    """Weighted blend of the rule score and the available ML score(s).

    Rule signals (domain age, redirect chain, reputation, crypto patterns,
    VirusTotal, Google Safe Browsing) are the source of truth and account
    for `1 - ML_AGGREGATE_WEIGHT` of the final score (default 80%). The
    enabled ML models share the remaining `ML_AGGREGATE_WEIGHT` equally
    (default 20%, averaged across enabled models). With no enabled ML
    models, the rule score is returned unchanged.

    This is intentionally conservative: a misfiring URL classifier that
    labels youtube.com at 98.5% malicious moves the final score by at most
    ~20 points instead of dragging it from "safe" to "high" on its own.
    """
    rule_score = clamp_score(rule_score)
    if isinstance(ml_results, dict) or ml_results is None:
        ml_results = [ml_results]

    enabled_scores = [
        float(r["score"]) for r in ml_results if r and r.get("enabled")
    ]
    if not enabled_scores:
        return clamp_score(rule_score)

    ml_weight = ML_AGGREGATE_WEIGHT
    rule_weight = 1.0 - ml_weight
    ml_mean = sum(enabled_scores) / len(enabled_scores)
    blended = (rule_weight * float(rule_score)) + (ml_weight * ml_mean)

    ml_signal_names = {"ML Risk Model", "ML Risk Model (EfficientNet)"}
    non_ml_high = any(
        item.get("severity") == "high" and item.get("check") not in ml_signal_names
        for item in signals
    )
    # When deterministic rule signals fire "high" (e.g. blocklist hit, VT
    # detection), preserve the high-risk floor — ML's confidence shouldn't
    # talk us out of a known-bad signal. But never the other way around:
    # ML alone cannot push the score into the danger band.
    ml_says_benign = max(enabled_scores) < 40
    if non_ml_high and blended < 75 and not ml_says_benign:
        blended = 75.0
    # If every ML input is confidently benign AND no rule signal flagged
    # high-risk, allow the score to drift slightly below the rule score
    # to reward consensus — but cap how far it can drop.
    if not non_ml_high and max(enabled_scores) <= 15:
        blended = min(blended, max(float(rule_score), 34.0))
    return clamp_score(blended)

def verdict_with_ml(base_verdict, final_score, ml_results, signals):
    """Compose the user-facing verdict text.

    ML inputs are intentionally NOT mentioned in the user-facing copy — the
    classifier names ("url_classifier.joblib") and raw probabilities are
    confusing for end users and risk eroding trust when the model misfires.
    ML's contribution lives inside `final_score` already via blend_ml_score,
    and the raw distribution is still returned in the response's `mlRisk`
    field for backend logging.
    """
    # `base_verdict` / `ml_results` are accepted for API parity with callers
    # but no longer affect the user-visible string.
    del base_verdict, ml_results
    overall_risk = risk_from_score(final_score)
    high_checks = [item["check"] for item in signals if item["severity"] == "high"]
    medium_checks = [item["check"] for item in signals if item["severity"] == "medium"]

    if overall_risk == "high":
        if high_checks:
            return f"This QR code shows high-risk indicators in {', '.join(high_checks[:3])}. Do not continue unless you can independently verify the destination and sender."
        return "This QR code lands in SafeScan's high-risk range. Do not continue unless you can independently verify the destination and sender."
    if overall_risk == "suspicious":
        checks = medium_checks or high_checks
        if checks:
            return f"This QR code looks suspicious because {', '.join(checks[:3])} need review. Continue only after confirming the domain, redirect path, and wallet action."
        return "This QR code lands in SafeScan's review range. Confirm the destination before taking action."
    return "SafeScan did not find strong phishing or wallet-drain indicators in this QR payload. Still verify the destination before connecting a wallet or sending funds."

def threat_type_for_analysis(overall_risk, signals, ml_results=None):
    """Threat type label shown to the user.

    Prefer the most severe deterministic rule signal — those are explainable
    (e.g. "Domain Age", "VirusTotal Reputation"). Only fall back to the ML
    label when the overall risk is already high AND no rule signal qualifies,
    so a misfiring URL classifier can't single-handedly label a known-good
    domain as "Malicious QR".
    """
    if overall_risk == "safe":
        return "Benign"
    ml_signal_names = {"ML Risk Model", "ML Risk Model (EfficientNet)"}
    first_high = next((item for item in signals if item["severity"] == "high" and item["check"] not in ml_signal_names), None)
    if first_high:
        return first_high["check"]
    if isinstance(ml_results, dict) or ml_results is None:
        ml_results = [ml_results]
    # Only let ML drive the threat type when the overall risk is already
    # high — i.e. the blended score independently agrees this looks bad.
    if overall_risk == "high" and any(
        r and r.get("enabled") and (r.get("bucket") == "malicious" or r.get("label") == "Malicious")
        for r in ml_results
    ):
        return "Malicious QR"
    return "Suspicious QR"

def mock_analysis_response(target_url):
    normalized = normalize_url(target_url)
    signals = [
        signal("Domain Age", "8 days old", "high", "Domain registered less than 30 days ago, a common phishing indicator.", False),
        signal("VirusTotal Reputation", "12/90 engines flagged", "high", "Multiple reputation engines flagged this destination as unsafe.", False),
        signal("Redirect Chain", "2 redirect hops detected", "medium", "The QR destination redirects before reaching the final landing page.", False),
        signal("URL Shortener", "Shortener found in chain", "medium", "Shortened URLs can hide the true destination from users.", False),
        signal("TLD Risk", "Non-standard TLD .xyz", "low", "The domain uses a TLD that appears frequently in disposable campaigns.", False),
    ]
    verdict = "This QR code shows multiple high-risk signals, including a newly registered domain and reputation engine detections. Treat it as a likely phishing or wallet-drain attempt unless you can independently verify the sender."
    return {
        "url": normalized,
        "overallRisk": "high",
        "confidenceScore": 91,
        "verdict": verdict,
        "signals": signals,
        "scannedAt": datetime.utcnow().isoformat() + "Z"
    }

def check_url_reputation(target_url):
    try:
        target_url = validate_public_url(target_url)
    except SafeScanError as exc:
        return {
            "provider": "SafeScan URL Guard",
            "status": "BLOCKED",
            "matches": ["SSRF_BLOCKED"],
            "detail": str(exc)
        }
    if not api_key:
        return {
            "provider": "Google Safe Browsing",
            "status": "UNCONFIGURED",
            "matches": [],
            "detail": "Set GOOGLE_SAFE_BROWSING_API_KEY to enable live reputation checks."
        }

    payload = {
        "client" : {"clientId": "safescan-qr" , "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url" : target_url}]
        }
    }
    try:
        response = requests.post(safe_browsing_url, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
    except requests.RequestException as exc:
        return {
            "provider": "Google Safe Browsing",
            "status": "ERROR",
            "matches": [],
            "detail": f"Reputation lookup failed: {type(exc).__name__}"
        }

    matches = result.get("matches", [])
    return {
        "provider": "Google Safe Browsing",
        "status": "MALICIOUS" if matches else "CLEAR",
        "matches": [match.get("threatType", "UNKNOWN_THREAT") for match in matches],
        "detail": "Known unsafe URL match found." if matches else "No known unsafe URL match returned."
    }

def google_reputation_signal(target_url):
    reputation = check_url_reputation(target_url)
    if reputation["status"] == "MALICIOUS":
        result = ", ".join(reputation["matches"]) or "Unsafe match"
        return signal("Google Safe Browsing", result, "high", "Google Safe Browsing returned a known unsafe threat match.", False)
    if reputation["status"] == "CLEAR":
        return signal("Google Safe Browsing", "No matches", "low", "Google Safe Browsing did not return a known unsafe match.", True)
    return signal("Google Safe Browsing", reputation["status"], "low", reputation["detail"], True)

def virustotal_url_id(target_url):
    encoded = base64.urlsafe_b64encode(target_url.encode("utf-8")).decode("utf-8")
    return encoded.rstrip("=")

def virustotal_reputation_signal(target_url):
    if not VIRUSTOTAL_API_KEY:
        return signal("VirusTotal Reputation", "Not configured", "low", "Set VIRUSTOTAL_API_KEY to enable VirusTotal v3 reputation checks.", True)

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url_id = virustotal_url_id(target_url)
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8)
        if response.status_code == 404:
            scan_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": target_url}, timeout=8)
            scan_response.raise_for_status()
            return signal("VirusTotal Reputation", "Scan submitted", "low", "VirusTotal did not have a cached verdict, so the URL was submitted for analysis.", True)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        return signal("VirusTotal Reputation", "Lookup failed", "low", f"VirusTotal lookup failed: {type(exc).__name__}", True)

    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    flagged = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    total = sum(int(value or 0) for value in stats.values()) or 90
    severity = "high" if flagged else "low"
    return signal(
        "VirusTotal Reputation",
        f"{flagged}/{total} engines flagged",
        severity,
        "VirusTotal engines flagged this URL." if flagged else "VirusTotal did not report malicious or suspicious engine detections.",
        flagged == 0
    )

def inspect_redirects(target_url):
    try:
        responses = follow_safe_redirects(target_url)
    except SafeScanError as exc:
        return {
            "status": "BLOCKED",
            "count": 0,
            "final_url": target_url,
            "detail": str(exc)
        }
    except requests.RequestException as exc:
        return {
            "status": "ERROR",
            "count": 0,
            "final_url": target_url,
            "detail": f"Redirect inspection failed: {type(exc).__name__}"
        }

    response = responses[-1]
    return {
        "status": "OK",
        "count": max(0, len(responses) - 1),
        "final_url": response.url,
        "detail": "Redirect chain inspected."
    }

def trace_redirect_chain(target_url):
    try:
        all_responses = follow_safe_redirects(target_url)
    except SafeScanError as exc:
        return {
            "signal": signal("Redirect Chain", "Blocked internal redirect target", "high", str(exc), False),
            "redirectChain": []
        }
    except requests.TooManyRedirects:
        return {
            "signal": signal("Redirect Chain", "More than 10 redirects", "high", "The URL exceeded the 10-hop redirect limit.", False),
            "redirectChain": []
        }
    except requests.RequestException as exc:
        return {
            "signal": signal("Redirect Chain", "Inspection failed", "low", f"Redirect inspection failed: {type(exc).__name__}", True),
            "redirectChain": []
        }

    def _site_key(host):
        """Approximate eTLD+1: strip common subdomain prefixes (www., m., mobile.)
        and reduce to the last two dot-labels so apex/www/mobile variants of the
        same site compare equal."""
        h = (host or "").lower().strip(".")
        for prefix in ("www.", "m.", "mobile.", "amp.", "en.", "us."):
            if h.startswith(prefix):
                h = h[len(prefix):]
                break
        parts = h.split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else h

    # SSO / federated-auth indicators. If any hop matches one of these, the
    # cross-domain redirect is almost certainly a legitimate auth bounce
    # (school portal -> idp -> portal, app -> oauth provider -> app, etc.)
    # rather than a wallet-drain or phishing chain.
    SSO_HOST_PREFIXES = ("idp.", "auth.", "sso.", "login.", "accounts.", "id.", "signin.", "secure.")
    SSO_HOST_SUFFIXES = (
        ".okta.com", ".auth0.com", ".onelogin.com", ".duosecurity.com",
        ".pingidentity.com", ".ping.cloud", ".cas.edu",
        "accounts.google.com", "login.microsoftonline.com",
        "login.live.com", "appleid.apple.com", "login.yahoo.com",
        "github.com/login", "shibboleth",
    )
    SSO_PATH_TOKENS = (
        "/login", "/signin", "/sign-in", "/sso", "/saml", "/openid",
        "/oauth", "/oauth2", "/auth/callback", "/cas/login", "/idp",
        "/shibboleth", "/adfs/ls", "/auth/realms/",
    )

    def _looks_like_sso(host, path):
        host_l = (host or "").lower()
        path_l = (path or "").lower()
        if any(host_l.startswith(p) for p in SSO_HOST_PREFIXES):
            return True
        if any(host_l.endswith(s) or s in host_l for s in SSO_HOST_SUFFIXES):
            return True
        if any(tok in path_l for tok in SSO_PATH_TOKENS):
            return True
        return False

    original_domain = urlparse(target_url).hostname or ""
    original_site = _site_key(original_domain)
    chain = []
    domain_changed = False
    has_shortener = False
    saw_sso_hop = False
    returned_to_origin = False
    for item in all_responses:
        item_url = item.url
        parsed = urlparse(item_url)
        domain = parsed.hostname or ""
        # Only flag a "domain change" when the redirect actually leaves the
        # site (e.g. bit.ly -> malware.tk), not for apex->www or m.* variants
        # of the same eTLD+1.
        site = _site_key(domain)
        changed = bool(original_site and domain and site != original_site)
        domain_changed = domain_changed or changed
        has_shortener = has_shortener or domain.lower().removeprefix("www.") in URL_SHORTENERS
        if _looks_like_sso(domain, parsed.path):
            saw_sso_hop = True
        if original_site and site == original_site and changed is False:
            # We returned to the original site at some hop (typical for
            # SSO: portal -> idp -> portal).
            returned_to_origin = True
        chain.append({"url": item_url, "domain": domain, "statusCode": item.status_code, "domainChanged": changed})

    hop_count = max(0, len(chain) - 1)
    # SSO is only "recognized" when it's a typical bounce: at least one hop
    # to an identity provider, returns to the original site, no shortener,
    # and short overall (3 hops max). Anything more elaborate stays graded
    # by the normal rules below.
    sso_flow = (
        saw_sso_hop and returned_to_origin and not has_shortener and hop_count <= 3
    )
    # Severity gradient:
    #   - shorteners or >2 hops or (2 hops AND cross-domain): high
    #   - single cross-domain hop (e.g. twitter.com -> x.com): medium
    #   - hops within the same site (apex<->www, etc.): low
    is_high = has_shortener or hop_count > 2 or (hop_count >= 2 and domain_changed)
    is_medium = (hop_count >= 1 and domain_changed) or hop_count == 2
    # Recognized SSO/auth bounces are normal web auth, not phishing -
    # treat the whole chain as low severity (passes).
    if sso_flow:
        is_high = False
        is_medium = False
    severity = "high" if is_high else ("medium" if is_medium else "low")
    suspicious = is_high or is_medium
    details = []
    if hop_count > 2:
        details.append("more than 2 redirect hops")
    if domain_changed and not sso_flow:
        details.append("final or intermediate domain differs from the original")
    if has_shortener:
        details.append("known URL shortener appears in the chain")
    if sso_flow:
        details.append("recognized SSO/auth bounce (cross-domain hop into a federated identity provider and back)")
    if sso_flow:
        description = f"Recognized SSO/auth bounce ({hop_count} hop(s) into a federated identity provider and back)."
        result_label = f"{hop_count} hop(s) (SSO)"
    elif not details:
        description = "Redirect chain is simple."
        result_label = f"{hop_count} hop(s)"
    else:
        description = "Suspicious redirect pattern: " + ", ".join(details) + "."
        result_label = f"{hop_count} hop(s)"
    return {
        "signal": signal("Redirect Chain", result_label, severity, description, not suspicious),
        "redirectChain": chain
    }

def parse_rdap_creation_date(events):
    for event in events or []:
        if event.get("eventAction") in ("registration", "domain registration", "creation"):
            date_value = event.get("eventDate")
            if date_value:
                try:
                    return datetime.fromisoformat(date_value.replace("Z", "+00:00")).replace(tzinfo=None)
                except ValueError:
                    return None
    return None

def parse_rdap_event_date(events, actions):
    actions = set(actions)
    for event in events or []:
        if event.get("eventAction") in actions:
            return event.get("eventDate")
    return None

def extract_domain_for_age(target_url):
    parsed = urlparse(normalize_url(target_url))
    return (parsed.hostname or "").lower().removeprefix("www.")

def domain_age_days(created_date):
    created = datetime.fromisoformat(created_date.replace("Z", "+00:00")).replace(tzinfo=None)
    return max(0, (datetime.utcnow() - created).days)

def domain_age_risk_level(age_days):
    if age_days is None:
        return "unknown"
    if age_days > 365:
        return "established"
    if age_days > 180:
        return "recent"
    return "new"

def format_domain_age(age_days):
    if age_days is None:
        return "Age unknown"
    years = age_days // 365
    months = (age_days % 365) // 30
    days = age_days % 30
    if years:
        return f"{years} year{'s' if years != 1 else ''}, {months} month{'s' if months != 1 else ''}"
    if months:
        return f"{months} month{'s' if months != 1 else ''}, {days} day{'s' if days != 1 else ''}"
    return f"{age_days} day{'s' if age_days != 1 else ''}"

def extract_rdap_registrar(rdap):
    registrar = rdap.get("registrar")
    if registrar:
        return registrar if isinstance(registrar, str) else registrar.get("name") or registrar.get("handle")
    for entity in rdap.get("entities", []) or []:
        vcard = entity.get("vcardArray", [])
        rows = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 else []
        for row in rows:
            if isinstance(row, list) and len(row) > 3 and row[0] == "fn":
                return row[3]
        if entity.get("handle"):
            return entity.get("handle")
    return None

def unknown_domain_age_result(domain):
    return {
        "domain": domain,
        "registeredOn": None,
        "expiresOn": None,
        "registrar": None,
        "ageInDays": None,
        "ageLabel": "Age unknown",
        "riskLevel": "unknown",
        "riskLabel": "Age unknown",
        "riskDetail": "WHOIS/RDAP data unavailable.",
    }

def lookup_domain_age_result(target_url):
    domain = extract_domain_for_age(target_url)
    if not domain:
        return unknown_domain_age_result("")
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        response.raise_for_status()
        rdap = response.json()
    except (requests.RequestException, ValueError):
        return unknown_domain_age_result(domain)

    events = rdap.get("events", [])
    registered_on = parse_rdap_event_date(events, ("registration", "domain registration", "creation"))
    expires_on = parse_rdap_event_date(events, ("expiration", "expiry"))
    registrar = extract_rdap_registrar(rdap)
    try:
        age_days = domain_age_days(registered_on) if registered_on else None
    except ValueError:
        age_days = None
    risk_level = domain_age_risk_level(age_days)
    risk_copy = {
        "established": ("Established domain", "Registered over a year ago."),
        "recent": ("Relatively new", "Registered within the last year."),
        "new": ("Very new domain", "High phishing risk - under 6 months old."),
        "unknown": ("Age unknown", "WHOIS/RDAP data unavailable."),
    }
    risk_label, risk_detail = risk_copy[risk_level]
    return {
        "domain": domain,
        "registeredOn": registered_on,
        "expiresOn": expires_on,
        "registrar": registrar,
        "ageInDays": age_days,
        "ageLabel": format_domain_age(age_days),
        "riskLevel": risk_level,
        "riskLabel": risk_label,
        "riskDetail": risk_detail,
    }

def check_domain_intelligence(target_url):
    normalized = normalize_url(target_url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return signal("Domain Intelligence", "No domain", "medium", "No valid domain could be extracted from the payload.", False)

    tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    tld_signal = None
    if tld in HIGH_RISK_TLDS:
        tld_signal = signal("TLD Risk", f"High-risk TLD {tld}", "low", f"The domain uses {tld}, which appears often in disposable phishing campaigns.", False)

    domain_age = lookup_domain_age_result(normalized)
    if domain_age["riskLevel"] == "unknown":
        base = signal("Domain Age", "Lookup unavailable", "low", "Domain registration lookup could not be completed.", True)
        base["domainAge"] = domain_age
        return [base, tld_signal] if tld_signal else [base]

    age_days = domain_age["ageInDays"]
    if domain_age["riskLevel"] == "new":
        severity = "high"
        passed = False
    elif domain_age["riskLevel"] == "recent":
        severity = "medium"
        passed = False
    else:
        severity = "low"
        passed = True
    registrar = domain_age.get("registrar") or "Unknown"
    base = signal("Domain Age", domain_age["ageLabel"], severity, f"Domain age from RDAP. Registrar: {registrar}.", passed)
    base["domainAge"] = domain_age
    return [base, tld_signal] if tld_signal else [base]

def check_crypto_pattern_signals(target_url):
    parsed = urlparse(target_url)
    haystack_parts = [target_url, parsed.query, parsed.fragment]
    for _, value in parse_qsl(parsed.query, keep_blank_values=True):
        haystack_parts.append(value)
    haystack = " ".join(haystack_parts)
    lower = haystack.lower()
    found = []

    solana_patterns = ("transferchecked", "drainwallet", "sweeptokens", "sign-message", "signmessage")
    for pattern in solana_patterns:
        if pattern in lower:
            found.append(signal("Crypto Pattern", pattern, "high", f"Found {pattern}, a wallet-drain or token-transfer signature pattern.", False))

    if "approve" in lower and ("uint256" in lower or "ffffffffffffffff" in lower or "max" in lower):
        found.append(signal("Ethereum Approval Pattern", "approve max uint256", "high", "The payload appears to request a maximum token approval.", False))

    base58_pattern = r"(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{32,44}(?![A-Za-z0-9])"
    base58_hits = re.findall(base58_pattern, parsed.query + " " + parsed.fragment)
    if base58_hits:
        found.append(signal("Solana Address Placement", f"{len(base58_hits)} address-like value(s)", "high", "Base58 wallet addresses appear inside query parameters or hash fragments.", False))

    for blocked in MALICIOUS_CONTRACT_BLOCKLIST:
        if blocked.lower() in lower:
            found.append(signal("Known Malicious Contract", blocked, "high", "The payload contains an address from the SafeScan MVP blocklist.", False))

    if not found:
        found.append(signal("Crypto Pattern", "No wallet-drain pattern found", "low", "No known Solana/Ethereum wallet-drain signature patterns were detected.", True))
    return found

def generate_ai_verdict(signals):
    score = score_from_signals(signals)
    overall_risk = risk_from_score(score)
    high_checks = [item["check"] for item in signals if item["severity"] == "high"]
    medium_checks = [item["check"] for item in signals if item["severity"] == "medium"]

    if high_checks:
        verdict = f"This QR code shows high-risk indicators in {', '.join(high_checks[:3])}. Do not continue unless you can independently verify the destination and sender."
    elif medium_checks:
        verdict = f"This QR code looks suspicious because {', '.join(medium_checks[:3])} need review. Continue only after confirming the domain, redirect path, and wallet action."
    else:
        verdict = "SafeScan did not find strong phishing or wallet-drain indicators in this QR payload. Still verify the destination before connecting a wallet or sending funds."

    fallback = {"overallRisk": overall_risk, "confidenceScore": score, "verdict": verdict}
    analyst_prompt = (
        "You are a QR security analyst. Review these SafeScan signal objects and return JSON only with "
        "overallRisk as safe, suspicious, or high; confidenceScore from 0-100; and verdict as a two-sentence "
        "plain-English explanation. Weight high severity at 40 points each capped at 80, medium at 15, low at 5, "
        "and push new-domain + redirect + wallet-pattern combinations to 90+.\n\n"
        f"Signals JSON:\n{json.dumps(signals)}"
    )

    try:
        if ANTHROPIC_API_KEY:
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                json={
                    "model": os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
                    "max_tokens": 300,
                    "system": "Return structured JSON only. Do not include markdown.",
                    "messages": [{"role": "user", "content": analyst_prompt}]
                },
                timeout=10
            )
            response.raise_for_status()
            content = response.json()["content"][0]["text"]
            return json.loads(content)
        if OPENAI_API_KEY:
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}", "content-type": "application/json"},
                json={
                    "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": "You are a QR security analyst. Return structured JSON only."},
                        {"role": "user", "content": analyst_prompt}
                    ]
                },
                timeout=10
            )
            response.raise_for_status()
            return json.loads(response.json()["choices"][0]["message"]["content"])
    except (requests.RequestException, KeyError, IndexError, ValueError, json.JSONDecodeError):
        return fallback

    return fallback

async def analyze_full_pipeline(target_url, qr_image=None):
    normalized = validate_public_url(target_url)
    if MOCK_MODE:
        return mock_analysis_response(normalized)

    fast_path_ok, fast_path_reason = should_short_circuit(normalized)
    if fast_path_ok:
        # Run only the cheap reputation check before declaring safe. If Google
        # Safe Browsing flags the URL (compromised popular site, abused open
        # redirect that slipped past the screen, etc.) we fall through to the
        # full pipeline for a real verdict.
        gsb_signal = await asyncio.to_thread(google_reputation_signal, normalized)
        if gsb_signal.get("passed", False) and gsb_signal.get("severity") == "low":
            allowlist_signal = signal(
                "Allowlist match",
                f"{allowlist_registrable_domain(normalized.split('//', 1)[-1].split('/', 1)[0])} on Tranco top 10K",
                "low",
                "SafeScan recognized this destination as a widely-trafficked, popular domain that passed structural safety screening (HTTPS, no homograph chars, no shorteners, no redirect parameters). The full ML and reputation pipeline was skipped because no expensive analysis is warranted; Google Safe Browsing was still consulted for compromised-site detection.",
                True,
            )
            fast_signals = sorted([allowlist_signal, gsb_signal], key=severity_rank)
            fast_score = clamp_score(8)
            return {
                "url": normalized,
                "overallRisk": "safe",
                "confidenceScore": fast_score,
                "ruleScore": fast_score,
                "mlRisk": {"enabled": False, "reason": "allowlist short-circuit"},
                "threatType": "Benign popular destination",
                "verdict": "safe",
                "signals": fast_signals,
                "virusTotal": None,
                "domainAge": None,
                "redirectChain": [],
                "scannedAt": datetime.utcnow().isoformat() + "Z",
                "fastPath": {"hit": True, "reason": "tranco_allowlist"},
            }
        # GSB returned a non-trivial signal - fall through to full pipeline.

    vt_result = virustotal_seed_result(normalized)
    domain_task = asyncio.to_thread(check_domain_intelligence, normalized)
    redirect_task = asyncio.to_thread(trace_redirect_chain, normalized)
    reputation_task = asyncio.to_thread(check_reputation_signals, normalized)
    crypto_task = asyncio.to_thread(check_crypto_pattern_signals, normalized)
    input_source = "uploaded_qr" if qr_image is not None else "generated_qr"
    ml_task = asyncio.to_thread(classify_qr_with_ml, normalized, qr_image, input_source)
    domain_result, redirect_result, reputation_signals, crypto_signals, ml_result = await asyncio.gather(
        domain_task, redirect_task, reputation_task, crypto_task, ml_task
    )

    signals = []
    signals.extend(domain_result if isinstance(domain_result, list) else [domain_result])
    domain_age = next((item.get("domainAge") for item in signals if item.get("domainAge")), None)
    signals.append(redirect_result["signal"])
    signals.extend(reputation_signals)
    signals.append(virustotal_breakdown_signal(vt_result))
    signals.extend(crypto_signals)
    # ML signal is kept around so the score blend + audit trail can use it,
    # but it's NOT appended to the user-visible signals list by default —
    # exposing classifier internals ("url_classifier.joblib 98.5% malicious")
    # is confusing UX, especially when the trained model misfires on safe
    # consumer domains. Flip SAFESCAN_ML_SIGNAL_VISIBLE=true to show it
    # again for debugging.
    ml_signal = ml_signal_from_result(ml_result, label="ML Risk Model", description_prefix="EfficientNet QR classifier")
    if ml_signal and ML_SIGNAL_VISIBLE:
        signals.append(ml_signal)
    signals = sorted(signals, key=severity_rank)
    ai_verdict = generate_ai_verdict(signals)
    final_score = blend_ml_score(ai_verdict["confidenceScore"], ml_result, signals)
    overall_risk = risk_from_score(final_score)

    return {
        "url": normalized,
        "overallRisk": overall_risk,
        "confidenceScore": final_score,
        "ruleScore": clamp_score(ai_verdict["confidenceScore"]),
        "mlRisk": ml_result,
        "threatType": threat_type_for_analysis(overall_risk, signals, ml_result),
        "verdict": verdict_with_ml(ai_verdict["verdict"], final_score, ml_result, signals),
        "signals": signals,
        "virusTotal": vt_result,
        "domainAge": domain_age,
        "redirectChain": redirect_result.get("redirectChain", []),
        "scannedAt": datetime.utcnow().isoformat() + "Z"
    }

def check_reputation_signals(target_url):
    return [google_reputation_signal(target_url)]

def is_url_like(value):
    return bool(re.match(r"^https?://", value, re.IGNORECASE) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", value, re.IGNORECASE))

def normalize_url(target_url):
    trimmed = target_url.strip()
    if not re.match(r"^https?://", trimmed, re.IGNORECASE):
        return f"https://{trimmed}"
    return trimmed

def alpha_solana_pay_url():
    if not ALPHA_SOLANA_RECIPIENT:
        return ""

    params = []
    if ALPHA_SOLANA_AMOUNT_SOL:
        params.append(("amount", ALPHA_SOLANA_AMOUNT_SOL))
    if ALPHA_SOLANA_LABEL:
        params.append(("label", ALPHA_SOLANA_LABEL))
    if ALPHA_SOLANA_MESSAGE:
        params.append(("message", ALPHA_SOLANA_MESSAGE))
    params.append(("memo", "SafeScan Alpha"))

    query = "&".join(f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in params)
    return f"solana:{ALPHA_SOLANA_RECIPIENT}?{query}" if query else f"solana:{ALPHA_SOLANA_RECIPIENT}"

def alpha_stripe_checkout_url(request: Request):
    if not ALPHA_STRIPE_PAYMENT_LINK:
        return ""

    user = get_session_user(request)
    params = []
    if user:
        if user.get("email"):
            params.append(("prefilled_email", user["email"]))
        if user.get("google_id"):
            params.append(("client_reference_id", user["google_id"]))

    if not params:
        return ALPHA_STRIPE_PAYMENT_LINK

    separator = "&" if "?" in ALPHA_STRIPE_PAYMENT_LINK else "?"
    return f"{ALPHA_STRIPE_PAYMENT_LINK}{separator}{urlencode(params)}"

def record_alpha_subscription_purchase(request: Request, provider="stripe"):
    user = get_session_user(request)
    if not user:
        return None

    purchased_at = now_iso()
    metadata = {
        "source": "alpha_success_page",
        "ipHash": hash_ip(request_ip(request)),
        "userAgent": request.headers.get("user-agent", ""),
    }
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO alpha_subscriptions
                (id, user_id, email, tier, provider, status, purchased_at,
                 stripe_payment_link, client_reference_id, metadata, created_at, updated_at)
            VALUES (?, ?, ?, 'alpha_premium', ?, 'active', ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, tier, provider) DO UPDATE SET
                email = excluded.email,
                status = 'active',
                stripe_payment_link = excluded.stripe_payment_link,
                client_reference_id = excluded.client_reference_id,
                metadata = excluded.metadata,
                updated_at = excluded.updated_at
            """,
            (
                make_id("sub"),
                user["google_id"],
                user["email"],
                provider,
                purchased_at,
                ALPHA_STRIPE_PAYMENT_LINK if provider == "stripe" else None,
                user["google_id"],
                json.dumps(metadata),
                purchased_at,
                purchased_at,
            ),
        )
    return {**user, "purchased_at": purchased_at}

def extract_urls(text):
    return re.findall(r"https?://[^\s<>'\"]+", text, flags=re.IGNORECASE)

def _truncate_description(value, limit=90):
    value = (value or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "..."

def _qr_field_value(payload, field):
    searchable = payload[5:] if payload.upper().startswith("WIFI:") else payload
    match = re.search(rf"(?:^|[;\r\n]){re.escape(field)}:([^;\r\n]*)", searchable, flags=re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).replace("\\;", ";").strip()

def describe_qr_action(payload_type, normalized):
    if payload_type == "URL":
        parsed = urlparse(normalized)
        host = parsed.hostname or normalized
        path = parsed.path or "/"
        if any(marker in normalized.lower() for marker in (".apk", ".exe", ".dmg", ".pkg", ".zip", "download")):
            return f"Open a browser link on {host} that appears to start or offer a download."
        if any(marker in normalized.lower() for marker in ("approve", "permit", "signature", "sign-message", "claim", "airdrop")):
            return f"Open a browser link on {host} that may lead into a wallet, claim, approval, or signature flow."
        return f"Open a browser link on {host}{_truncate_description(path, 48)}."
    if payload_type == "Wi-Fi":
        ssid = _qr_field_value(normalized, "S")
        auth = _qr_field_value(normalized, "T") or "unspecified security"
        network = f" named {_truncate_description(ssid, 48)}" if ssid else ""
        return f"Ask the device to join a Wi-Fi network{network} using {auth}."
    if payload_type == "SMS":
        target = normalized.split(":", 1)[1].split(":", 1)[0] if ":" in normalized else ""
        recipient = f" to {_truncate_description(target, 48)}" if target else ""
        return f"Open a prefilled text message{recipient}; it should still require review before sending."
    if payload_type == "Email":
        parsed = urlparse(normalized)
        recipient = parsed.path or normalized.replace("mailto:", "", 1)
        target = f" to {_truncate_description(recipient, 48)}" if recipient else ""
        return f"Open a prefilled email{target}; it should still require review before sending."
    if payload_type == "Crypto/payment":
        scheme = normalized.split(":", 1)[0].lower()
        return f"Open a {scheme} wallet or payment request; approval should happen only inside the wallet."
    if payload_type == "Contact card":
        name = _qr_field_value(normalized, "FN") or _qr_field_value(normalized, "N")
        contact = f" for {_truncate_description(name, 48)}" if name else ""
        return f"Offer to add contact details{contact} to the address book."
    if payload_type == "Calendar":
        title = _qr_field_value(normalized, "SUMMARY")
        event = f" named {_truncate_description(title, 48)}" if title else ""
        return f"Offer to add a calendar event{event}."
    if payload_type == "JSON/custom":
        return "Pass structured data to an app or service that understands this QR format."
    return "Display the decoded text payload without launching a standard browser, wallet, or message flow."

def detect_payload(raw_payload):
    payload = raw_payload.strip()
    upper = payload.upper()

    if is_url_like(payload):
        return "URL", "Open website", normalize_url(payload)
    if upper.startswith("WIFI:"):
        return "Wi-Fi", "Join Wi-Fi network", payload
    if "BEGIN:VCARD" in upper:
        return "Contact card", "Import contact", payload
    if upper.startswith(("SMSTO:", "SMS:")):
        return "SMS", "Open prefilled text message", payload
    if upper.startswith("MAILTO:"):
        return "Email", "Open prefilled email", payload
    if upper.startswith(("SOLANA:", "BITCOIN:", "ETHEREUM:")):
        return "Crypto/payment", "Open wallet or payment request", payload
    if upper.startswith("BEGIN:VEVENT") or "BEGIN:VCALENDAR" in upper:
        return "Calendar", "Add calendar event", payload

    try:
        json.loads(payload)
        return "JSON/custom", "Run app-specific data flow", payload
    except ValueError:
        return "Plain text", "Display text payload", payload

def analyze_non_url_payload(raw_payload):
    payload_type, action, normalized = detect_payload(raw_payload)
    action_description = describe_qr_action(payload_type, normalized)
    embedded_urls = extract_urls(normalized)
    score = 0
    status = "SAFE"
    threat_class = f"{payload_type}: {action}"
    reasons = []

    if payload_type == "Wi-Fi":
        score = 25
        status = "CAUTION"
        if "T:WEP" in normalized.upper() or "T:NOPASS" in normalized.upper():
            score = 45
            threat_class = "Wi-Fi network with weak or open security"
            reasons.append(risk_reason("Weak Wi-Fi security", "medium", "The QR can join a WEP or open network. Confirm the network is trusted before joining."))
        else:
            threat_class = "Wi-Fi join request: review network name before joining"
            reasons.append(risk_reason("Wi-Fi join request", "low", "The QR changes device network state, so the SSID and security type should be reviewed."))
    elif payload_type in ("SMS", "Email"):
        score = 35
        status = "CAUTION"
        threat_class = f"{payload_type} action: review recipient and message before sending"
        reasons.append(risk_reason(f"{payload_type} action", "medium", "The QR can open a prefilled message. Review the recipient and body before sending."))
    elif payload_type == "Contact card":
        score = 20
        status = "CAUTION"
        threat_class = "Contact import: review names, phone numbers, and links before saving"
        reasons.append(risk_reason("Contact import", "low", "The QR can add contact data to your device. Review names, phone numbers, and links."))
    elif payload_type == "Crypto/payment":
        score = 60
        status = "CAUTION"
        threat_class = "Wallet/payment request: verify destination before approving"
        reasons.append(risk_reason("Wallet or payment request", "high", "The QR can launch a crypto wallet or payment flow. Verify the destination before approving."))
    elif payload_type == "Calendar":
        score = 20
        status = "CAUTION"
        threat_class = "Calendar event: review event details before adding"
        reasons.append(risk_reason("Calendar write request", "low", "The QR can add an event to the calendar. Review the organizer, links, and date."))
    elif payload_type == "JSON/custom":
        score = 30
        status = "CAUTION"
        threat_class = "Custom app payload: inspect app-specific action before running"
        reasons.append(risk_reason("Custom app payload", "medium", "The QR contains structured data that another app may interpret."))

    if embedded_urls:
        score = max(score, 45)
        status = "CAUTION"
        threat_class = f"{payload_type} containing embedded URL: inspect destination before action"
        reasons.append(risk_reason("Embedded URL detected", "medium", "The payload contains a link hidden inside another QR action."))

    risky_words = ("password", "seed", "recovery", "verify", "login", "wallet", "bank", "urgent")
    if any(word in normalized.lower() for word in risky_words):
        score = max(score, 55)
        status = "CAUTION"
        threat_class = f"{payload_type} includes sensitive or urgency language"
        reasons.append(risk_reason("Sensitive language", "medium", "The payload references wallet, password, login, recovery, or urgency wording."))

    if not reasons:
        reasons.append(risk_reason("No risky payload pattern detected", "low", "SafeScan did not find wallet-drainer, credential, redirect, or suspicious QR action indicators."))

    return {
        "status": status,
        "score": str(score),
        "threat_class": threat_class,
        "source": "SafeScan Payload Analyzer",
        "normalized": normalized,
        "payload_type": payload_type,
        "action_description": action_description,
        "reputation": {"provider": "SafeScan Payload Analyzer", "status": "NOT_APPLICABLE", "matches": [], "detail": "Reputation lookup only runs for URL payloads."},
        "reasons": reasons
    }

def analyze_url_payload(raw_payload):
    normalized = validate_public_url(raw_payload)
    action_description = describe_qr_action("URL", normalized)
    parsed = urlparse(normalized)
    lower_url = normalized.lower()
    score = 0
    threat_class = "Safe Destination"
    reasons = []

    cached_status = get_cached_result(normalized)
    if cached_status:
        return {
            "status": cached_status,
            "score": "95" if cached_status == "MALICIOUS" else "0",
            "threat_class": "Phishing/Malware Risk" if cached_status == "MALICIOUS" else "Safe Destination",
            "source": "Local Cache",
            "normalized": normalized,
            "payload_type": "URL",
            "action_description": action_description,
            "reputation": {"provider": "Local Cache", "status": cached_status, "matches": [], "detail": "Cached verdict from the last 24 hours."},
            "reasons": [risk_reason("Cached reputation verdict", "high" if cached_status == "MALICIOUS" else "low", "This URL was recently scanned and reused from local cache.")]
        }

    reputation = check_url_reputation(normalized)
    redirect_result = inspect_redirects(normalized)
    status = "MALICIOUS" if reputation["status"] == "MALICIOUS" else "SAFE"

    if parsed.scheme != "https":
        score += 20
        threat_class = "Non-HTTPS destination"
        reasons.append(risk_reason("Non-HTTPS destination", "medium", "The decoded URL does not use HTTPS, which makes spoofing and interception riskier."))
    if parsed.hostname and parsed.hostname.endswith((".top", ".zip", ".click", ".shop")):
        score += 20
        threat_class = "Higher-risk URL destination"
        reasons.append(risk_reason("Higher-risk top-level domain", "medium", "The domain uses a TLD often seen in disposable phishing or scam campaigns."))
    if any(keyword in lower_url for keyword in ("download", ".apk", ".exe", ".dmg", ".pkg", ".zip")):
        score += 45
        threat_class = "Download or installer link: review before opening"
        reasons.append(risk_reason("Download or installer link", "high", "The URL appears to trigger a download or installer path."))
    if any(keyword in lower_url for keyword in ("verify", "login", "password", "wallet", "seed", "recovery")):
        score += 25
        threat_class = "Credential or wallet-themed URL"
        reasons.append(risk_reason("Credential or wallet wording", "high", "The URL contains login, seed, recovery, password, verify, or wallet language."))
    if any(keyword in lower_url for keyword in ("drain", "drainer", "approve", "approval", "permit", "signature", "sign-message", "airdrop", "claim")):
        score += 35
        threat_class = "Wallet drain signature pattern"
        reasons.append(risk_reason("Wallet drain signature pattern", "high", "The URL uses claim, approve, signature, permit, or drainer language often seen in wallet-draining flows."))
    if redirect_result["count"] > 0:
        score += min(30, redirect_result["count"] * 15)
        threat_class = "Redirecting destination"
        reasons.append(risk_reason("Redirects detected", "medium", f"The URL redirects {redirect_result['count']} time(s) before landing on {redirect_result['final_url']}."))
    elif redirect_result["status"] == "ERROR":
        reasons.append(risk_reason("Redirect inspection unavailable", "low", redirect_result["detail"]))

    if status == "MALICIOUS":
        score = 95
        threat_class = "Phishing/Malware Risk"
        reasons.insert(0, risk_reason("Google Safe Browsing match", "high", "Live reputation lookup returned a known unsafe threat match."))
    elif score >= 45:
        status = "CAUTION"
    else:
        score = 0

    if reputation["status"] == "CLEAR":
        reasons.append(risk_reason("Reputation lookup clear", "low", "Google Safe Browsing did not return a known unsafe match for this URL."))
    elif reputation["status"] in ("UNCONFIGURED", "ERROR"):
        reasons.append(risk_reason("Reputation lookup unavailable", "low", reputation["detail"]))
    if not reasons:
        reasons.append(risk_reason("No suspicious URL pattern detected", "low", "SafeScan did not find redirect, wallet-drainer, credential, or high-risk URL indicators."))

    save_to_cache(normalized, status)
    return {
        "status": status,
        "score": str(min(score, 95)),
        "threat_class": threat_class,
        "source": "SafeScan Engine",
        "normalized": normalized,
        "payload_type": "URL",
        "action_description": action_description,
        "reputation": reputation,
        "reasons": reasons
    }

def analyze_qr_payload(raw_payload):
    payload_type, _, normalized = detect_payload(raw_payload)
    if payload_type == "URL":
        return analyze_url_payload(normalized)
    return analyze_non_url_payload(normalized)

def pipeline_response_to_template_analysis(pipeline_response):
    overall_risk = pipeline_response["overallRisk"]
    signals = pipeline_response.get("signals", [])
    first_high = next((item for item in signals if item["severity"] == "high"), None)
    first_signal = first_high or (signals[0] if signals else None)
    return {
        "status": status_from_risk(overall_risk),
        "score": str(pipeline_response["confidenceScore"]),
        "threat_class": pipeline_response.get("threatType") or threat_type_for_analysis(overall_risk, signals, pipeline_response.get("mlRisk")) or (first_signal["check"] if first_signal else "SafeScan Risk Engine"),
        "source": "SafeScan Core Risk Engine",
        "normalized": pipeline_response["url"],
        "payload_type": "URL",
        "action_description": describe_qr_action("URL", pipeline_response["url"]),
        "overallRisk": overall_risk,
        "verdict": pipeline_response["verdict"],
        "reputation": {"provider": "SafeScan Core Risk Engine", "status": overall_risk.upper(), "matches": [], "detail": pipeline_response["verdict"]},
        "reasons": signals,
        "virusTotal": pipeline_response.get("virusTotal"),
        "domainAge": pipeline_response.get("domainAge"),
        "mlRisk": pipeline_response.get("mlRisk"),
        "ruleScore": pipeline_response.get("ruleScore")
    }

async def analyze_embedded_url_payload(raw_payload, embedded_url, qr_image=None):
    payload_type, _, normalized_payload = detect_payload(raw_payload)
    pipeline_response = await analyze_full_pipeline(embedded_url, qr_image)
    analysis = pipeline_response_to_template_analysis(pipeline_response)
    pipeline_score = clamp_score(analysis.get("score"))
    final_score = max(45, pipeline_score)
    final_risk = risk_from_score(final_score)

    embedded_reason = risk_reason(
        "Embedded URL detected",
        "medium",
        "The QR payload is not a plain URL, but it contains a URL that SafeScan extracted and analyzed with the full URL pipeline."
    )
    analysis["score"] = str(final_score)
    analysis["status"] = status_from_risk(final_risk)
    analysis["overallRisk"] = final_risk
    analysis["payload_type"] = payload_type
    analysis["threat_class"] = f"{payload_type} containing embedded URL: {analysis['threat_class']}"
    analysis["action_description"] = (
        f"{describe_qr_action(payload_type, normalized_payload)} "
        f"SafeScan extracted and analyzed the embedded URL: {analysis['normalized']}."
    )
    analysis["verdict"] = (
        f"The QR contains an embedded URL inside a {payload_type.lower()} payload, so SafeScan analyzed "
        f"{analysis['normalized']} before allowing navigation. {analysis.get('verdict', '')}"
    ).strip()
    analysis["reasons"] = [embedded_reason, *analysis.get("reasons", [])]
    analysis["embeddedPayload"] = normalized_payload
    return analysis

def decode_qr_image(image):
    Image, ImageEnhance, ImageFilter, ImageOps, decode = image_libs()
    image = ImageOps.exif_transpose(image)

    def normalize_candidate(candidate):
        if candidate.mode not in ("RGB", "L"):
            candidate = candidate.convert("RGB")
        return candidate

    def grayscale_candidates(candidate):
        gray = ImageOps.grayscale(candidate)
        yield gray

        contrast = ImageOps.autocontrast(gray)
        yield contrast

        sharpened = contrast.filter(ImageFilter.SHARPEN)
        yield sharpened

        high_contrast = ImageEnhance.Contrast(sharpened).enhance(1.8)
        yield high_contrast

        for source in (gray, contrast, high_contrast):
            for threshold in (55, 70, 85, 95, 115, 135, 155, 185):
                yield source.point(lambda pixel, limit=threshold: 255 if pixel > limit else 0)

    def candidate_images():
        yield normalize_candidate(image)
        yield from grayscale_candidates(image)

        max_side = max(image.size)
        if max_side < 1400:
            scale = 1400 / max_side
            resized = image.resize(
                (int(image.width * scale), int(image.height * scale)),
                Image.Resampling.LANCZOS
            )
            yield resized
            yield from grayscale_candidates(resized)

    for candidate in candidate_images():
        zxing_result = decode_barcodes_with_zxing(candidate, qr_only=True)
        if zxing_result:
            return zxing_result

        for angle in (0, 90, 180, 270):
            rotated = candidate if angle == 0 else candidate.rotate(angle, expand=True)
            try:
                from pyzbar.pyzbar import ZBarSymbol
                decoded = decode(rotated, symbols=[ZBarSymbol.QRCODE])
            except Exception:
                decoded = decode(rotated)
            if decoded:
                return decoded

        zxing_result = decode_barcodes_with_zxing(candidate)
        if zxing_result:
            return zxing_result
    return []

def _decode_qr_from_pil_image(image):
    decoded_qr = decode_qr_image(image)
    if not decoded_qr:
        return None, None
    return decoded_qr[0].data.decode("utf-8", errors="replace"), image.copy()

def _looks_like_svg(contents, filename="", content_type=""):
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    if name.endswith(".svg") or "svg" in ctype:
        return True
    prefix = contents[:512].lstrip().lower()
    return prefix.startswith(b"<svg") or b"<svg" in prefix

def _looks_like_pdf(contents, filename="", content_type=""):
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    return name.endswith(".pdf") or "pdf" in ctype or contents[:5] == b"%PDF-"

def _svg_candidates(contents):
    candidates = [contents]
    try:
        root = ElementTree.fromstring(contents)
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        nested_svgs = root.findall(".//svg:svg", namespace)
        if not nested_svgs:
            nested_svgs = [node for node in root.iter() if str(node.tag).endswith("svg") and node is not root]
        for nested in nested_svgs[:3]:
            candidates.append(ElementTree.tostring(nested, encoding="utf-8"))
    except Exception:
        pass
    return candidates

def _local_name(tag):
    return str(tag).split("}", 1)[-1]

def _float_attr(element, name, default=0.0):
    value = element.attrib.get(name)
    if value is None:
        return default
    match = re.match(r"[-+]?\d*\.?\d+", str(value).strip())
    return float(match.group(0)) if match else default

def _parse_viewbox(element, fallback_width=100.0, fallback_height=100.0):
    raw = element.attrib.get("viewBox") or element.attrib.get("viewbox")
    if raw:
        parts = [float(part) for part in re.split(r"[\s,]+", raw.strip()) if part]
        if len(parts) == 4 and parts[2] and parts[3]:
            return tuple(parts)
    return (0.0, 0.0, fallback_width, fallback_height)

def _render_basic_svg_qr(svg_bytes):
    Image, _, _, _, _ = image_libs()
    try:
        root = ElementTree.fromstring(svg_bytes)
    except Exception:
        return None

    root_width = _float_attr(root, "width", 2000.0)
    root_height = _float_attr(root, "height", 2000.0)
    _, _, view_width, view_height = _parse_viewbox(root, root_width, root_height)
    output_size = 2000
    image = Image.new("RGB", (output_size, output_size), "white")
    from PIL import ImageDraw
    draw = ImageDraw.Draw(image)

    def map_point(transform, x, y):
        origin_x, origin_y, min_x, min_y, scale_x, scale_y = transform
        return (
            origin_x + (x - min_x) * scale_x,
            origin_y + (y - min_y) * scale_y,
        )

    root_transform = (0.0, 0.0, 0.0, 0.0, output_size / view_width, output_size / view_height)

    def walk(element, transform):
        tag = _local_name(element.tag)
        fill = (element.attrib.get("fill") or "").lower()

        if tag == "svg" and element is not root:
            x = _float_attr(element, "x")
            y = _float_attr(element, "y")
            width = _float_attr(element, "width", 0.0)
            height = _float_attr(element, "height", width)
            min_x, min_y, child_view_width, child_view_height = _parse_viewbox(element, width, height)
            child_x, child_y = map_point(transform, x, y)
            child_right, child_bottom = map_point(transform, x + width, y + height)
            child_transform = (
                child_x,
                child_y,
                min_x,
                min_y,
                (child_right - child_x) / child_view_width,
                (child_bottom - child_y) / child_view_height,
            )

            has_path = any(_local_name(child.tag) == "path" for child in element)
            if has_path and width and height:
                # QR finder patterns are often embedded as compound SVG paths.
                # Draw the standard 7x7 finder ring so scanners see the anchor.
                x0, y0 = child_x, child_y
                x1, y1 = child_right, child_bottom
                module_w = (x1 - x0) / 7
                module_h = (y1 - y0) / 7
                draw.rectangle([x0, y0, x1, y1], fill="black")
                draw.rectangle([x0 + module_w, y0 + module_h, x1 - module_w, y1 - module_h], fill="white")

            for child in element:
                walk(child, child_transform)
            return

        if tag == "rect":
            x = _float_attr(element, "x")
            y = _float_attr(element, "y")
            width = _float_attr(element, "width")
            height = _float_attr(element, "height")
            x0, y0 = map_point(transform, x, y)
            x1, y1 = map_point(transform, x + width, y + height)
            color = "white" if fill in ("#ffffff", "white") else "black" if fill in ("#000000", "black") else None
            if color:
                draw.rectangle([x0, y0, x1, y1], fill=color)

        elif tag == "polygon" and fill in ("#000000", "black"):
            raw_points = element.attrib.get("points", "")
            values = [float(part) for part in re.split(r"[\s,]+", raw_points.strip()) if part]
            points = [map_point(transform, values[index], values[index + 1]) for index in range(0, len(values) - 1, 2)]
            if points:
                draw.polygon(points, fill="black")

        for child in element:
            walk(child, transform)

    walk(root, root_transform)
    return image

def decode_qr_upload(contents, filename="", content_type=""):
    Image, _, _, _, _ = image_libs()

    try:
        with Image.open(io.BytesIO(contents)) as image:
            payload, qr_image = _decode_qr_from_pil_image(image)
            if payload:
                return payload, qr_image
    except Exception:
        pass

    if _looks_like_svg(contents, filename, content_type):
        for svg_bytes in _svg_candidates(contents):
            image = _render_basic_svg_qr(svg_bytes)
            if image is None:
                continue
            try:
                payload, qr_image = _decode_qr_from_pil_image(image)
                if payload:
                    return payload, qr_image
            finally:
                image.close()

    if _looks_like_pdf(contents, filename, content_type):
        try:
            import fitz
            document = fitz.open(stream=contents, filetype="pdf")
            try:
                for page_index in range(min(document.page_count, MAX_QR_PDF_PAGES)):
                    page = document.load_page(page_index)
                    pixmap = page.get_pixmap(matrix=fitz.Matrix(2.5, 2.5), alpha=False)
                    with Image.open(io.BytesIO(pixmap.tobytes("png"))) as image:
                        payload, qr_image = _decode_qr_from_pil_image(image)
                        if payload:
                            return payload, qr_image
            finally:
                document.close()
        except Exception:
            pass

    return None, None

class DecodedBarcode:
    def __init__(self, text, barcode_format="Unknown"):
        self.data = text.encode("utf-8", errors="replace")
        self.type = barcode_format

def decode_barcodes_with_zxing(image, qr_only=False):
    try:
        import zxingcpp
    except ImportError:
        return []
    results = []
    formats = zxingcpp.BarcodeFormat.QRCode if qr_only else zxingcpp.BarcodeFormat.All
    binarizers = (
        zxingcpp.Binarizer.LocalAverage,
        zxingcpp.Binarizer.GlobalHistogram,
        zxingcpp.Binarizer.FixedThreshold,
        zxingcpp.Binarizer.BoolCast,
    )
    text_modes = (zxingcpp.TextMode.Plain, zxingcpp.TextMode.HRI)
    for binarizer in binarizers:
        for text_mode in text_modes:
            for is_pure in (False, True):
                try:
                    results = zxingcpp.read_barcodes(
                        image,
                        formats=formats,
                        try_rotate=True,
                        try_downscale=True,
                        try_invert=True,
                        text_mode=text_mode,
                        binarizer=binarizer,
                        is_pure=is_pure,
                    )
                except Exception:
                    continue
                if results:
                    break
            if results:
                break
        if results:
            break
    decoded = []
    for result in results:
        text = (getattr(result, "text", "") or "").strip()
        if not text:
            continue
        decoded.append(DecodedBarcode(text, str(getattr(result, "format", "Unknown"))))
    return decoded

qr_app = FastAPI()
app = qr_app


@qr_app.get("/health", include_in_schema=False)
async def health_check():
    """Lightweight liveness probe - does not touch the DB."""
    return {"status": "ok"}


@qr_app.get("/health/live", include_in_schema=False)
async def health_live():
    return {"status": "alive"}


@qr_app.get("/health/ready", include_in_schema=False)
async def health_ready():
    try:
        with sqlite3.connect(database_path(), timeout=2) as conn:
            conn.execute("SELECT 1")
        storage = storage_backend_status()
        database = database_storage_status()
        return {"status": "ready", "storage": storage["backend"], "database": database}
    except Exception as exc:
        return JSONResponse({"status": "not_ready", "error": str(exc)}, status_code=503)


@qr_app.get("/metrics", include_in_schema=False)
async def metrics(request: Request):
    ip = request_ip(request)
    allowed = [item.strip() for item in os.getenv("METRICS_ALLOWED_IPS", "127.0.0.1,::1").split(",") if item.strip()]
    if ip not in allowed:
        raise HTTPException(status_code=403)
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


qr_app.mount("/static", StaticFiles(directory="static"), name="static")

qr_app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=None,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Device-Fingerprint"],
    expose_headers=["X-Request-Id"],
    max_age=600,
)

@qr_app.middleware("http")
async def enforce_origin(request: Request, call_next):
    origin = request.headers.get("origin")
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and origin:
        google_sign_in_callback = request.url.path == "/auth/google"
        if origin not in ALLOWED_ORIGINS and not google_sign_in_callback:
            return JSONResponse({"error": "Origin not allowed."}, status_code=403)
    return await call_next(request)

@qr_app.middleware("http")
async def rls_context_middleware(request: Request, call_next):
    try:
        user = get_session_user(request)
        if user:
            set_rls_context(
                user_id=user.get("google_id") or user.get("email"),
                role=user.get("role", "user"),
                email=user.get("email"),
            )
        else:
            set_rls_context(None, "guest")
        response = await call_next(request)
        return response
    finally:
        clear_rls_context()

@qr_app.middleware("http")
async def remember_me_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/static/") or request.cookies.get(SESSION_COOKIE_NAME):
        return await call_next(request)

    remembered_user, rotated_token = validate_and_rotate_remember_me(request)
    if remembered_user:
        request.state.remembered_user = remembered_user
        session_id = create_session(remembered_user["google_id"], request)
        response = await call_next(request)
        set_session_cookie(response, session_id)
        set_remember_me_cookie(response, rotated_token)
        return response

    response = await call_next(request)
    if request.cookies.get(REMEMBER_ME_COOKIE_NAME):
        clear_remember_me_cookie(response)
    return response

CSP_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://accounts.google.com https://apis.google.com https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https://lh3.googleusercontent.com https://ssl.gstatic.com https://www.gstatic.com",
    "connect-src 'self' https://safescan-qr.onrender.com https://accounts.google.com https://safebrowsing.googleapis.com https://www.virustotal.com https://api.virustotal.com https://api.mainnet-beta.solana.com https://api.anthropic.com https://api.openai.com https://cdn.jsdelivr.net",
    "frame-src https://accounts.google.com https://www.youtube.com https://www.youtube-nocookie.com",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "upgrade-insecure-requests",
])

PERMISSIONS_POLICY = ", ".join([
    "camera=()",
    "microphone=()",
    "geolocation=()",
    "payment=()",
])

def apply_security_headers(request: Request, response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = CSP_POLICY
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
    if "Server" in response.headers:
        del response.headers["Server"]
    if "X-Powered-By" in response.headers:
        del response.headers["X-Powered-By"]
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    elif request.url.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response

@qr_app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    return apply_security_headers(request, response)

async def wallet_nonce_cleanup_loop():
    while True:
        cleanup_wallet_nonces()
        await asyncio.sleep(15 * 60)

@qr_app.on_event("startup")
async def start_wallet_nonce_cleanup():
    cleanup_persistent_sessions()
    asyncio.create_task(wallet_nonce_cleanup_loop())

@qr_app.middleware("http")
async def security_headers_and_rate_limits(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/static/"):
        public_limit = enforce_rate_limit(request, "public", 300, 15 * 60)
        if public_limit:
            return apply_security_headers(request, public_limit)
    if path.startswith("/api/"):
        api_limit = enforce_rate_limit(request, "api", 100, 15 * 60)
        if api_limit:
            return apply_security_headers(request, api_limit)
    return await call_next(request)


@qr_app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.monotonic()
    if request.url.path in ("/api/scan", "/api/scan/file", "/search_qr_api"):
        ACTIVE_SCANS.inc()
    try:
        response = await call_next(request)
        return response
    finally:
        duration = time.monotonic() - start
        status = getattr(locals().get("response", None), "status_code", 500)
        REQUEST_COUNT.labels(method=request.method, path=request.url.path, status=str(status)).inc()
        REQUEST_LATENCY.labels(path=request.url.path).observe(duration)
        if request.url.path in ("/api/scan", "/api/scan/file", "/search_qr_api"):
            ACTIVE_SCANS.dec()

@qr_app.exception_handler(SafeScanError)
async def safe_scan_error_handler(request: Request, exc: SafeScanError):
    return JSONResponse({"error": str(exc)}, status_code=exc.status_code)

@qr_app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    safe_messages = {
        400: "Invalid request.",
        401: "Authentication required.",
        403: "You do not have permission to do this.",
        404: "Not found.",
        429: "Too many requests. Please slow down.",
    }
    return JSONResponse({"error": safe_messages.get(exc.status_code, exc.detail)}, status_code=exc.status_code)

@qr_app.exception_handler(PermissionError)
async def permission_error_handler(request: Request, exc: PermissionError):
    return JSONResponse({"error": str(exc) or "You do not have permission to do this."}, status_code=403)

@qr_app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    print({"error": str(exc), "path": request.url.path})
    return JSONResponse({"error": "Something went wrong on our end."}, status_code=500)

def admin_context(request, title, page, data=None, owner_only=False):
    admin_user = get_session_user(request)
    if not admin_user or not has_role(admin_user, "admin"):
        return RedirectResponse("/", status_code=303)
    if owner_only and not has_role(admin_user, "owner"):
        return RedirectResponse("/", status_code=303)
    context = {
        "request": request,
        "title": title,
        "page": page,
        "data": data or {},
        "admin_user": admin_user,
        "is_owner": has_role(admin_user, "owner"),
        "avatar": admin_avatar(admin_user.get("email")),
    }
    return templates.TemplateResponse("admin_shell.html", context)

def fetch_admin_users(search="", status="", role="", tier="", page=1, limit=25):
    clauses = []
    params = []
    if search:
        clauses.append("(u.email LIKE ? OR u.google_id LIKE ? OR COALESCE(u.display_name, '') LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if status:
        clauses.append("u.status = ?")
        params.append(status)
    if role:
        clauses.append("u.role = ?")
        params.append(role)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    offset = max(0, page - 1) * limit
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute(f"SELECT COUNT(*) FROM users u {where}", params).fetchone()[0]
        rows = [dict(row) for row in conn.execute(
            f"""
            SELECT u.*, COALESCE(s.scan_count, 0) AS scan_count,
                   COALESCE(w.address, s.wallet_address) AS wallet_address,
                   w.verified AS wallet_verified, w.sol_balance, w.tx_count,
                   w.wallet_age_days, w.onchain_verified_at,
                   COALESCE(s.tokens_sent, 0) AS tokens_sent,
                   COALESCE(s.airdrop_tokens_sent, 0) AS airdrop_tokens_sent,
                   s.airdrop_sent_at,
                   COALESCE((SELECT COUNT(*) FROM referrals r WHERE r.referrer_email = u.email AND r.counted = 1), 0) AS referral_count,
                   COALESCE((SELECT COUNT(*) FROM fraud_flags f WHERE f.user_id = u.email AND f.reviewed = 0), 0) AS fraud_flags
            FROM users u
            LEFT JOIN scans s ON s.email = u.email
            LEFT JOIN wallets w ON w.user_id = u.email AND w.verified = 1
            {where}
            ORDER BY COALESCE(u.last_login_at, u.last_login, u.created_at) DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset]
        )]
    for row in rows:
        scan_count = int(row.get("scan_count") or 0)
        referrals = int(row.get("referral_count") or 0)
        tier_name = airdrop_tier(scan_count, referrals)
        row["tier"] = "Registered" if tier_name == "Pending" else tier_name
    if tier:
        rows = [row for row in rows if row["tier"].lower() == tier.lower()]
    return {"rows": rows, "total": total, "page": page, "limit": limit, "pages": max(1, (total + limit - 1) // limit)}

def fetch_user_detail(email):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            """
            SELECT u.*, COALESCE(w.address, s.wallet_address) AS wallet_address,
                   w.verified AS wallet_verified, w.sol_balance, w.tx_count,
                   w.wallet_age_days, w.onchain_verified_at,
                   COALESCE(s.scan_count, 0) AS scan_count
            FROM users u
            LEFT JOIN scans s ON s.email = u.email
            LEFT JOIN wallets w ON w.user_id = u.email AND w.verified = 1
            WHERE u.email = ? OR u.google_id = ?
            """,
            (email, email)
        ).fetchone()
        flags = [dict(row) for row in conn.execute("SELECT * FROM fraud_flags WHERE user_id = ? ORDER BY created_at DESC LIMIT 50", (email,))]
        logs = [dict(row) for row in conn.execute("SELECT * FROM audit_logs WHERE actor_user_id = ? OR target_id = ? ORDER BY created_at DESC LIMIT 50", (email, email))]
        scans = [dict(row) for row in conn.execute("SELECT * FROM scan_history WHERE email = ? ORDER BY created_at DESC LIMIT 50", (email,))]
    return {"user": dict(user) if user else None, "flags": flags, "logs": logs, "scans": scans}

def dashboard_data():
    today = datetime.utcnow().date().isoformat()
    since_30 = (datetime.utcnow() - timedelta(days=30)).isoformat()
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        total_users = conn.execute("SELECT COUNT(*) FROM users WHERE status != 'deleted'").fetchone()[0]
        scans_today = conn.execute("SELECT COUNT(*) FROM scan_history WHERE created_at >= ?", (today,)).fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM scan_history WHERE verdict IN ('MALICIOUS', 'HIGH') OR risk_score >= 80").fetchone()[0]
        fraud_flags = conn.execute("SELECT COUNT(*) FROM fraud_flags WHERE reviewed = 0").fetchone()[0]
        recent_users = [dict(row) for row in conn.execute("SELECT u.*, COALESCE(w.address, s.wallet_address) AS wallet_address, COALESCE(s.scan_count, 0) AS scan_count FROM users u LEFT JOIN scans s ON s.email = u.email LEFT JOIN wallets w ON w.user_id = u.email AND w.verified = 1 ORDER BY COALESCE(u.created_at, u.last_login) DESC LIMIT 10")]
        recent_reports = [dict(row) for row in conn.execute("SELECT * FROM url_reports ORDER BY created_at DESC LIMIT 10")]
        activity = [dict(row) for row in conn.execute(
            """
            SELECT a.*,
                   COALESCE(actor_by_id.email, actor_by_email.email) AS actor_email
            FROM audit_logs a
            LEFT JOIN users actor_by_id ON actor_by_id.google_id = a.actor_user_id
            LEFT JOIN users actor_by_email ON lower(actor_by_email.email) = lower(a.actor_user_id)
            ORDER BY a.created_at DESC
            LIMIT 20
            """
        )]
        chart_rows = [dict(row) for row in conn.execute(
            "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total, SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) AS flagged FROM scan_history WHERE created_at >= ? GROUP BY day ORDER BY day",
            (since_30,)
        )]
        verdict_rows = [dict(row) for row in conn.execute("SELECT COALESCE(verdict, 'SAFE') AS verdict, COUNT(*) AS count FROM scan_history GROUP BY verdict")]
    return {
        "stats": [
            {"label": "Total Users", "value": total_users, "trend": "+0%", "icon": "users"},
            {"label": "QR Scans Today", "value": scans_today, "trend": "+0%", "icon": "scan"},
            {"label": "Malicious Blocked", "value": blocked, "trend": "+0%", "icon": "shield"},
            {"label": "Active Fraud Flags", "value": fraud_flags, "trend": "+0%", "icon": "flag", "danger": fraud_flags > 0},
        ],
        "recent_users": recent_users,
        "recent_reports": recent_reports,
        "activity": activity,
        "chart_rows": chart_rows,
        "verdict_rows": verdict_rows,
    }

def fetch_scans(search="", verdict="", user="", limit=100):
    clauses = []
    params = []
    if search:
        clauses.append("url LIKE ?")
        params.append(f"%{search}%")
    if verdict:
        clauses.append("verdict = ?")
        params.append(verdict)
    if user:
        clauses.append("email LIKE ?")
        params.append(f"%{user}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute(f"SELECT * FROM scan_history {where} ORDER BY created_at DESC LIMIT ?", params + [limit])]
        total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        flagged_today = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_score >= 80 AND created_at >= ?", (datetime.utcnow().date().isoformat(),)).fetchone()[0]
        avg_risk = conn.execute("SELECT AVG(risk_score) FROM scan_history WHERE created_at >= ?", ((datetime.utcnow() - timedelta(days=7)).isoformat(),)).fetchone()[0] or 0
    return {"rows": rows, "stats": {"total": total, "flagged_today": flagged_today, "avg_risk": round(avg_risk, 1), "common_tld": "n/a"}}

def fetch_reports(tab="reports"):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        reports = [dict(row) for row in conn.execute("SELECT * FROM url_reports ORDER BY created_at DESC LIMIT 200")]
        blocklist = [dict(row) for row in conn.execute("SELECT * FROM url_blocklist WHERE removed_at IS NULL ORDER BY created_at DESC LIMIT 200")]
    return {"reports": reports, "blocklist": blocklist, "tab": tab}

def fetch_waitlist(search="", limit=500):
    bounded_limit = max(1, min(int(limit or 500), 5000))
    normalized_search = (search or "").strip().lower()
    candidates = [database_path(), "/app/data/qr_cache.db", "/var/data/qr_cache.db"]
    seen_paths = []
    signups = {}
    total = 0
    for candidate in candidates:
        if not candidate or candidate in seen_paths or not os.path.exists(candidate):
            continue
        seen_paths.append(candidate)
        try:
            with sqlite3.connect(candidate) as conn:
                conn.row_factory = sqlite3.Row
                table = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'waitlist_signups'"
                ).fetchone()
                if not table:
                    continue
                rows = conn.execute(
                    "SELECT email, source, created_at FROM waitlist_signups ORDER BY created_at DESC LIMIT ?",
                    (bounded_limit,),
                ).fetchall()
        except sqlite3.Error:
            continue
        for row in rows:
            email = (row["email"] or "").strip().lower()
            if not email or (normalized_search and normalized_search not in email):
                continue
            existing = signups.get(email)
            current = dict(row)
            if not existing or str(current.get("created_at") or "") > str(existing.get("created_at") or ""):
                signups[email] = current
    rows = sorted(signups.values(), key=lambda row: row.get("created_at") or "", reverse=True)[:bounded_limit]
    total = len(signups)
    return {"rows": rows, "total": total, "filters": {"search": search}, "limit": bounded_limit}

def fetch_airdrop_data():
    users = fetch_admin_users(limit=10000)["rows"]
    wallet_users = [row for row in users if row.get("wallet_address")]
    tier_counts = {"Registered": 0, "Scanner": 0, "Referrer": 0, "Guardian": 0}
    for row in wallet_users:
        tier_counts[row["tier"]] = tier_counts.get(row["tier"], 0) + 1
        row["estimated_sqr"] = AIRDROP_TOKEN_ALLOCATIONS.get(row["tier"], 0)
        row["distribution_status"] = "sent" if row.get("tokens_sent") else ("blocked" if row.get("airdrop_status") in ("flagged", "disqualified") or row.get("fraud_flags") else ("qualified" if row["estimated_sqr"] > 0 else "pending"))
    flagged = [row for row in users if row.get("airdrop_status") == "flagged" or row.get("fraud_flags")]
    qualified = [
        row for row in wallet_users
        if row.get("distribution_status") == "qualified"
        and row.get("status") == "active"
        and row.get("airdrop_status") in ("eligible", "cleared")
    ]
    distributed_total = sum(int(row.get("airdrop_tokens_sent") or 0) for row in wallet_users)
    return {
        "wallet_users": wallet_users,
        "qualified": qualified,
        "tier_counts": tier_counts,
        "flagged": flagged,
        "estimated_total": sum(row.get("estimated_sqr", 0) for row in qualified),
        "distributed_total": distributed_total,
        "base_allocation": AIRDROP_BASE_ALLOCATION,
    }

def airdrop_tier(scan_count, referrals):
    if scan_count >= 50 and referrals >= 2:
        return "Guardian"
    if scan_count >= 5 and referrals >= 1:
        return "Referrer"
    if scan_count >= 5:
        return "Scanner"
    return "Pending"

def next_airdrop_milestone(scan_count, referrals):
    if scan_count < 5:
        return f"Scan {5 - scan_count} more QR code{'s' if 5 - scan_count != 1 else ''} to unlock Scanner."
    if referrals < 1:
        return "Invite 1 user with your referral link to unlock Referrer."
    if scan_count < 50 or referrals < 2:
        return "Scan 50 QR codes and invite multiple people to unlock Guardian."
    return "Guardian tier unlocked."

def fetch_fraud_data():
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute(
            """
            SELECT u.email, u.role, u.airdrop_status, COALESCE(u.fraud_score, 0) AS fraud_score,
                   COALESCE(w.address, s.wallet_address) AS wallet_address, COALESCE(s.scan_count, 0) AS scan_count,
                   COUNT(f.id) AS signal_count, MAX(f.severity) AS highest_severity, MAX(f.created_at) AS flag_date
            FROM users u
            LEFT JOIN scans s ON s.email = u.email
            LEFT JOIN wallets w ON w.user_id = u.email AND w.verified = 1
            JOIN fraud_flags f ON f.user_id = u.email AND f.reviewed = 0
            GROUP BY u.email
            ORDER BY fraud_score DESC, flag_date DESC
            """
        )]
    return {"rows": rows}

def fetch_audit_logs(search="", action="", target_type=""):
    clauses = []
    params = []
    if search:
        clauses.append("(a.actor_user_id LIKE ? OR actor_by_id.email LIKE ? OR actor_by_email.email LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if action:
        clauses.append("action = ?")
        params.append(action)
    if target_type:
        clauses.append("target_type = ?")
        params.append(target_type)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute(
            f"""
            SELECT a.*,
                   COALESCE(actor_by_id.email, actor_by_email.email) AS actor_email
            FROM audit_logs a
            LEFT JOIN users actor_by_id ON actor_by_id.google_id = a.actor_user_id
            LEFT JOIN users actor_by_email ON lower(actor_by_email.email) = lower(a.actor_user_id)
            {where}
            ORDER BY a.created_at DESC
            LIMIT 300
            """,
            params,
        )]
        actions = [row[0] for row in conn.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action")]
    return {"rows": rows, "actions": actions}

PRIVACY_POLICY_HTML = f"""
<h2>1. What We Collect</h2>
<p>SafeScan QR collects only what is needed to authenticate users, analyze QR payloads, prevent abuse, and operate the optional SQR airdrop program.</p>
<ul>
  <li>Google OAuth data: name, email, profile picture, Google ID, and login timestamp.</li>
  <li>Optional Solana wallet address supplied by the user for airdrop eligibility.</li>
  <li>QR scan payloads such as URLs analyzed for risk. Logged-in scans may be associated with the user's email for scan counts and fraud prevention.</li>
  <li>Referral link usage and referral counts.</li>
  <li>IP address hash, approximate region, browser type, device type, and session signals for fraud prevention and analytics.</li>
  <li>Cookies and local storage values for authentication state, consent state, referral state, wallet state, and local report queues.</li>
</ul>
<h2>2. Why We Collect It and Legal Basis</h2>
<ul>
  <li>Authentication: contractual necessity.</li>
  <li>Scan history and QR security delivery: legitimate interest in providing and improving security analysis.</li>
  <li>Airdrop eligibility, scan tiers, referrals, and wallet address: contractual necessity for the tier program.</li>
  <li>Analytics and abuse prevention: legitimate interest.</li>
  <li>Marketing emails: explicit consent only.</li>
</ul>
<h2>3. How Long We Keep It</h2>
<ul>
  <li>Scan logs: targeted for deletion after 90 days.</li>
  <li>Account data: until deletion is requested or after 2 years of inactivity.</li>
  <li>Wallet address: until the user disconnects it or deletes the account.</li>
  <li>Consent records: retained for 5 years to document legal compliance.</li>
</ul>
<h2>4. Who We Share It With</h2>
<p>We do not sell personal data and do not use advertising networks. We may share limited data with service providers only as needed:</p>
<ul>
  <li>Google for OAuth authentication and Google Safe Browsing URL reputation checks.</li>
  <li>VirusTotal for URL reputation checks. URL payloads may be sent, but user identity is not included.</li>
  <li>Anthropic or OpenAI for AI analysis. URL payloads and risk signals may be sent, but direct personal identifiers are excluded.</li>
  <li>Solana RPC providers for wallet interactions involving public blockchain data.</li>
  <li>Render.com for hosting infrastructure.</li>
</ul>
<h2>5. Cookies and Tracking</h2>
<p>SafeScan uses essential cookies/local storage for auth, consent, referral, wallet, and report state. Analytics is optional and should only run after consent where required.</p>
<h2>6. Your Rights</h2>
<p>EU/EEA users may exercise GDPR rights of access, erasure, rectification, restriction, portability, and objection. California users may exercise CCPA/CPRA rights to know, delete, correct, opt out of sale/sharing, limit sensitive personal information, and non-discrimination. Brazilian users may exercise LGPD rights including revoking consent and requesting information about public and private entities with whom data is shared. Canadian users are protected under PIPEDA principles: knowledge and consent, limited use, accuracy, safeguards, access, and the right to challenge compliance.</p>
<p>Use the <a href="/legal/data-request">Data Request portal</a> to submit requests.</p>
<h2>7. Children's Privacy</h2>
<p>SafeScan is not directed to children under 13. EU users under 16 require parental consent under GDPR Article 8. If we discover an underage user, we will delete associated data promptly.</p>
<h2>8. International Data Transfers</h2>
<p>Data is hosted in the United States. For EU users, transfers are intended to be covered by Standard Contractual Clauses or other appropriate safeguards where required.</p>
<h2>9. Security Measures</h2>
<ul>
  <li>TLS encryption in transit.</li>
  <li>Wallet addresses should be hashed or encrypted at rest as the product matures.</li>
  <li>OAuth tokens are not intentionally stored; SafeScan keeps only account/session references.</li>
  <li>Security incidents are tracked for GDPR Article 33 72-hour supervisory authority review and Article 34 user notice if high risk.</li>
</ul>
<h2>10. Contact</h2>
<p>Privacy requests: <a href="mailto:{ADMIN_EMAIL}">{ADMIN_EMAIL}</a>. A formal Data Protection Officer is not required at current scale but will be appointed upon reaching 5,000 EU users or when legally required.</p>
"""

TERMS_HTML = """
<h2>1. Acceptance of Terms</h2>
<p>By using SafeScan QR, you agree to these Terms. If you do not agree, do not use the service. You must be at least 13 globally, or 16 in the EU without parental consent.</p>
<h2>2. Description of Service</h2>
<p>SafeScan QR is an informational QR risk analysis tool. Risk verdicts are not guarantees of safety. The SQR airdrop program is discretionary, subject to change, and does not provide financial advice.</p>
<h2>3. User Accounts</h2>
<p>Google OAuth is used for authentication. You are responsible for account security. One account per person is allowed; multiple accounts for airdrop gaming may lead to disqualification. SafeScan may suspend accounts for abuse, fraud, bot activity, or security risk.</p>
<h2>4. Acceptable Use</h2>
<ul>
  <li>No automated bots to inflate scan counts or referrals.</li>
  <li>No intentional stress-testing or abuse of the risk engine.</li>
  <li>No reverse-engineering, scraping, or resale of scan results.</li>
  <li>No laundering, cloaking, or obscuring malicious URLs.</li>
  <li>No impersonating SafeScan in referral campaigns.</li>
</ul>
<h2>5. Airdrop Program Terms</h2>
<p>SQR has no guaranteed monetary value. Eligibility is tracked in SafeScan's database and may be checked against on-chain activity. SafeScan may disqualify fraudulent activity and may change timing or allocation at its sole discretion. Token receipt does not constitute investment advice or an offer of securities. The airdrop is unavailable where token distributions are prohibited or restricted, including jurisdictions where compliance cannot be satisfied.</p>
<h2>6. Intellectual Property</h2>
<p>The SafeScan name, UI, and product assets are proprietary. Users grant SafeScan a limited license to process submitted URLs and QR payloads for service delivery. SafeScan does not claim ownership of user scan data.</p>
<h2>7. Disclaimers and Limitation of Liability</h2>
<p>The service is provided as is, with no uptime guarantee at this stage. SafeScan is not liable for losses caused by acting on or ignoring a risk verdict. Liability is capped at $100 or the amount paid to SafeScan in the last 12 months, whichever is greater.</p>
<h2>8. Governing Law and Dispute Resolution</h2>
<p>These Terms are governed by Florida law. Disputes are resolved by binding arbitration under AAA rules, with a class action waiver. EU users retain the right to lodge complaints with their local supervisory authority.</p>
<h2>9. Changes to Terms</h2>
<p>SafeScan will provide 30 days notice before material changes where practical. Continued use means acceptance. Version history will be maintained at /legal/terms-history.</p>
"""

COOKIE_POLICY_HTML = """
<h2>Cookie Table</h2>
<table class="legal-table">
  <thead><tr><th>Cookie Name</th><th>Provider</th><th>Purpose</th><th>Type</th><th>Duration</th></tr></thead>
  <tbody>
    <tr><td>session token</td><td>SafeScan</td><td>Authentication session reference</td><td>Essential</td><td>Session</td></tr>
    <tr><td>consent-id</td><td>SafeScan</td><td>Stores consent record ID</td><td>Essential</td><td>12 months</td></tr>
    <tr><td>phishproofAirdropProfile</td><td>SafeScan local storage</td><td>Stores local demo profile and wallet state</td><td>Functional</td><td>Until cleared</td></tr>
    <tr><td>safeScanConsent</td><td>SafeScan local storage</td><td>Stores local consent choice so the banner does not reappear unnecessarily</td><td>Essential</td><td>12 months</td></tr>
    <tr><td>safeScanReports</td><td>SafeScan local storage</td><td>Stores local Block & Report queue</td><td>Functional</td><td>Until cleared</td></tr>
  </tbody>
</table>
<p>No third-party advertising cookies are used. If Google Analytics or similar analytics is added, it must be listed here before deployment and gated by consent where required.</p>
<h2>Disable Cookies</h2>
<p>You can manage cookies in <a href="https://support.google.com/chrome/answer/95647" target="_blank" rel="noopener noreferrer">Chrome</a>, <a href="https://support.mozilla.org/en-US/kb/clear-cookies-and-site-data-firefox" target="_blank" rel="noopener noreferrer">Firefox</a>, <a href="https://support.apple.com/guide/safari/manage-cookies-sfri11471/mac" target="_blank" rel="noopener noreferrer">Safari</a>, and <a href="https://support.microsoft.com/microsoft-edge" target="_blank" rel="noopener noreferrer">Edge</a>.</p>
"""

@qr_app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    return admin_context(request, "Dashboard", "dashboard", dashboard_data())

@qr_app.get("/admin/activity", response_class=HTMLResponse)
async def admin_activity(request: Request):
    return admin_context(request, "Activity Feed", "logs", fetch_audit_logs())

@qr_app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, search: str = Query(""), status: str = Query(""), role: str = Query(""), tier: str = Query(""), page: int = Query(1), flag: str = Query("")):
    data = fetch_admin_users(search=search, status=status, role=role, tier=tier, page=page)
    data.update({"filters": {"search": search, "status": status, "role": role, "tier": tier, "flag": flag}})
    if flag == "review":
        data["rows"] = [row for row in data["rows"] if row.get("fraud_flags")]
    return admin_context(request, "All Users", "users", data)

@qr_app.get("/admin/users/{email}/drawer", response_class=HTMLResponse)
async def admin_user_drawer(request: Request, email: str):
    admin_user = require_role_user(request, "admin")
    data = fetch_user_detail(email)
    if not data["user"]:
        raise HTTPException(status_code=404, detail="Not found.")
    return templates.TemplateResponse("admin_shell.html", {"request": request, "page": "user_drawer", "title": "User Detail", "data": data, "admin_user": admin_user, "is_owner": has_role(admin_user, "owner"), "avatar": admin_avatar(admin_user.get("email"))})

@qr_app.post("/admin/users/{email}/suspend")
async def admin_suspend_user(request: Request, email: str, action: str = Form("suspend")):
    admin_user = require_role_user(request, "admin")
    new_status = "active" if action == "unsuspend" else "suspended"
    with get_conn() as conn:
        conn.execute("UPDATE users SET status = ? WHERE email = ?", (new_status, email))
    audit_log("admin.user_unsuspended" if new_status == "active" else "admin.user_suspended", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=email)
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.post("/admin/users/{email}/role")
async def admin_change_role(request: Request, email: str, role: str = Form(...)):
    admin_user = require_role_user(request, "owner")
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid request.")
    with get_conn() as conn:
        conn.execute("UPDATE users SET role = ? WHERE email = ?", (role, email))
    audit_log("admin.role_changed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=email, metadata={"role": role})
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.post("/admin/users/{email}/delete")
async def admin_delete_user(request: Request, email: str, confirm: str = Form("")):
    admin_user = require_role_user(request, "owner")
    if confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Invalid request.")
    with get_conn() as conn:
        conn.execute("UPDATE users SET status = 'deleted', deleted_at = ?, airdrop_status = 'disqualified' WHERE email = ?", (now_iso(), email))
    audit_log("admin.user_deleted", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=email)
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.get("/admin/export/users")
async def admin_export_users(request: Request):
    admin_user = require_role_user(request, "owner")
    users = fetch_admin_users(limit=10000)["rows"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["email", "role", "status", "tier", "scan_count", "referral_count", "wallet_address", "created_at", "last_login_at"])
    writer.writeheader()
    for row in users:
        writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
    audit_log("admin.export", request=request, actor_user_id=admin_user.get("google_id"), target_type="users")
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=safescan-users.csv"})

@qr_app.get("/admin/scans", response_class=HTMLResponse)
async def admin_scans(request: Request, search: str = Query(""), verdict: str = Query(""), user: str = Query("")):
    return admin_context(request, "All Scans", "scans", fetch_scans(search=search, verdict=verdict, user=user))

@qr_app.get("/admin/waitlist", response_class=HTMLResponse)
async def admin_waitlist(request: Request, search: str = Query("")):
    return admin_context(request, "Waitlist", "waitlist", fetch_waitlist(search=search))

@qr_app.get("/admin/export/waitlist")
async def admin_export_waitlist(request: Request):
    owner = require_role_user(request, "owner")
    rows = fetch_waitlist(limit=5000)["rows"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["email", "source", "created_at"])
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
    audit_log("admin.export", request=request, actor_user_id=owner.get("google_id"), target_type="waitlist")
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=safescan-waitlist.csv"})

@qr_app.post("/admin/scans/{scan_id}/flag")
async def admin_flag_scan(request: Request, scan_id: str):
    admin_user = require_role_user(request, "admin")
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        assert_owns_row(conn, "scan_history", scan_id)
        scan = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Not found.")
        conn.execute("UPDATE scan_history SET verdict = 'MALICIOUS', risk_score = 100 WHERE id = ?", (scan_id,))
        conn.execute("INSERT OR IGNORE INTO url_blocklist VALUES (?, ?, ?, ?, ?, NULL)", (make_id("block"), scan["url"], "Admin confirmed malicious scan", admin_user.get("email"), now_iso()))
    audit_log("admin.url_flagged", request=request, actor_user_id=admin_user.get("google_id"), target_type="scan", target_id=scan_id)
    return RedirectResponse("/admin/scans", status_code=303)

@qr_app.get("/admin/reports", response_class=HTMLResponse)
async def admin_reports(request: Request, tab: str = Query("reports")):
    return admin_context(request, "Reported URLs", "reports", fetch_reports(tab=tab))

@qr_app.post("/admin/reports/{report_id}/action")
async def admin_report_action(request: Request, report_id: str, action: str = Form(...)):
    admin_user = require_role_user(request, "admin")
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        assert_owns_row(conn, "url_reports", report_id)
        report = conn.execute("SELECT * FROM url_reports WHERE id = ?", (report_id,)).fetchone()
        if not report:
            raise HTTPException(status_code=404, detail="Not found.")
        if action == "confirm":
            conn.execute("UPDATE url_reports SET status = 'confirmed_malicious', reviewed_at = ?, reviewed_by = ? WHERE id = ?", (now_iso(), admin_user.get("email"), report_id))
            conn.execute("INSERT OR IGNORE INTO url_blocklist VALUES (?, ?, ?, ?, ?, NULL)", (make_id("block"), report["url"], report["reason"], admin_user.get("email"), now_iso()))
        elif action == "dismiss":
            conn.execute("UPDATE url_reports SET status = 'dismissed', reviewed_at = ?, reviewed_by = ? WHERE id = ?", (now_iso(), admin_user.get("email"), report_id))
        elif action == "reanalyze":
            analysis = await analyze_full_pipeline(report["url"])
            conn.execute("UPDATE url_reports SET risk_score = ?, status = 'pending' WHERE id = ?", (int(analysis.get("confidenceScore") or 0), report_id))
        else:
            raise HTTPException(status_code=400, detail="Invalid request.")
    audit_log("admin.report_reviewed", request=request, actor_user_id=admin_user.get("google_id"), target_type="url_report", target_id=report_id, metadata={"action": action})
    return RedirectResponse("/admin/reports", status_code=303)

@qr_app.post("/admin/blocklist/{block_id}/remove")
async def admin_remove_block(request: Request, block_id: str):
    admin_user = require_role_user(request, "admin")
    with get_conn() as conn:
        assert_owns_row(conn, "url_blocklist", block_id)
        conn.execute("UPDATE url_blocklist SET removed_at = ? WHERE id = ?", (now_iso(), block_id))
    audit_log("admin.blocklist_removed", request=request, actor_user_id=admin_user.get("google_id"), target_type="blocklist", target_id=block_id)
    return RedirectResponse("/admin/reports?tab=blocklist", status_code=303)

@qr_app.get("/admin/risk-logs", response_class=HTMLResponse)
async def admin_risk_logs(request: Request):
    return admin_context(request, "Risk Engine Logs", "scans", fetch_scans(verdict="MALICIOUS"))

@qr_app.get("/admin/airdrop", response_class=HTMLResponse)
async def admin_airdrop(request: Request):
    return admin_context(request, "Tier Overview", "airdrop", fetch_airdrop_data())

@qr_app.post("/admin/airdrop/distribute", response_class=HTMLResponse)
async def admin_airdrop_distribute(request: Request):
    admin_user = require_role_user(request, "admin")
    try:
        from distribute import airdrop_sweep
        result = await airdrop_sweep()
        audit_log(
            "airdrop.sweep_executed",
            request=request,
            actor_user_id=admin_user.get("google_id"),
            target_type="airdrop",
            metadata={
                "qualified": result.get("eligible", 0),
                "sent": len(result.get("sent", [])),
                "totalTokens": result.get("total_tokens_sent", 0),
                "status": result.get("status")
            }
        )
        data = fetch_airdrop_data()
        data["distribution_result"] = result
        return admin_context(request, "Tier Overview", "airdrop", data)
    except Exception as exc:
        audit_log("airdrop.sweep_failed", request=request, actor_user_id=admin_user.get("google_id"), target_type="airdrop", metadata={"error": type(exc).__name__})
        data = fetch_airdrop_data()
        data["distribution_result"] = {"status": "failed", "error": "Airdrop sweep failed.", "error_type": type(exc).__name__}
        return admin_context(request, "Tier Overview", "airdrop", data)

@qr_app.get("/admin/airdrop/fraud", response_class=HTMLResponse)
async def admin_airdrop_fraud(request: Request):
    return admin_context(request, "Fraud Flags", "fraud", fetch_fraud_data())

@qr_app.get("/admin/airdrop/wallets", response_class=HTMLResponse)
async def admin_airdrop_wallets(request: Request):
    return admin_context(request, "Wallet Registry", "airdrop", fetch_airdrop_data())

@qr_app.post("/admin/airdrop/{email}/status")
async def admin_airdrop_status(request: Request, email: str, status: str = Form(...), reason: str = Form("")):
    admin_user = require_role_user(request, "admin")
    if status not in ("eligible", "flagged", "disqualified", "cleared"):
        raise HTTPException(status_code=400, detail="Invalid request.")
    with get_conn() as conn:
        conn.execute("UPDATE users SET airdrop_status = ? WHERE email = ?", (status, email))
    audit_log("admin.airdrop_status_changed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=email, metadata={"status": status, "reason": reason})
    return RedirectResponse("/admin/airdrop", status_code=303)

@qr_app.post("/admin/fraud/{email}/review")
async def admin_fraud_review(request: Request, email: str, outcome: str = Form(...), reason: str = Form("")):
    admin_user = require_role_user(request, "admin")
    if outcome not in ("cleared", "disqualified", "escalated"):
        raise HTTPException(status_code=400, detail="Invalid request.")
    status = "cleared" if outcome == "cleared" else ("disqualified" if outcome == "disqualified" else "flagged")
    with get_conn() as conn:
        conn.execute("UPDATE fraud_flags SET reviewed = 1, reviewed_by = ?, reviewed_at = ?, review_outcome = ? WHERE user_id = ? AND reviewed = 0", (admin_user.get("email"), now_iso(), outcome, email))
        conn.execute("UPDATE users SET airdrop_status = ? WHERE email = ?", (status, email))
    audit_log("admin.fraud_reviewed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=email, metadata={"outcome": outcome, "reason": reason})
    return RedirectResponse("/admin/airdrop/fraud", status_code=303)

@qr_app.get("/admin/audit-logs", response_class=HTMLResponse)
@qr_app.get("/admin/logs", response_class=HTMLResponse)
async def admin_logs(request: Request, search: str = Query(""), action: str = Query(""), target_type: str = Query(""), export: str = Query("")):
    data = fetch_audit_logs(search=search, action=action, target_type=target_type)
    if export == "csv":
        owner = require_role_user(request, "owner")
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=["created_at", "actor_user_id", "action", "target_type", "target_id", "ip_address", "user_agent", "metadata"])
        writer.writeheader()
        for row in data["rows"]:
            writer.writerow({key: row.get(key, "") for key in writer.fieldnames})
        audit_log("admin.export", request=request, actor_user_id=owner.get("google_id"), target_type="audit_logs")
        return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=safescan-audit-logs.csv"})
    return admin_context(request, "Audit Logs", "logs", data)

@qr_app.get("/admin/api-keys", response_class=HTMLResponse)
async def admin_api_keys(request: Request):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        keys = [dict(row) for row in conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC")]
    return admin_context(request, "API Keys", "api_keys", {"keys": keys}, owner_only=True)

@qr_app.post("/admin/api-keys")
async def admin_create_api_key(request: Request, name: str = Form(...), scopes: list[str] = Form([]), expires_at: str = Form("")):
    owner = require_role_user(request, "owner")
    raw_key = "sk_live_" + secrets.token_urlsafe(32)
    hint = raw_key[:14] + "..."
    with get_conn() as conn:
        conn.execute("INSERT INTO api_keys VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, NULL, NULL)", (make_id("key"), name[:80], hint, hashlib.sha256(raw_key.encode()).hexdigest(), json.dumps(scopes), owner.get("email"), now_iso(), expires_at or None))
    audit_log("api_key.created", request=request, actor_user_id=owner.get("google_id"), target_type="api_key", metadata={"name": name, "scopes": scopes})
    return admin_context(request, "API Keys", "api_key_created", {"raw_key": raw_key}, owner_only=True)

@qr_app.post("/admin/api-keys/{key_id}/revoke")
async def admin_revoke_api_key(request: Request, key_id: str):
    owner = require_role_user(request, "owner")
    with get_conn() as conn:
        assert_owns_row(conn, "api_keys", key_id)
        conn.execute("UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = ?", (now_iso(), key_id))
    audit_log("api_key.revoked", request=request, actor_user_id=owner.get("google_id"), target_type="api_key", target_id=key_id)
    return RedirectResponse("/admin/api-keys", status_code=303)

@qr_app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings(request: Request):
    return admin_context(request, "Settings", "settings", {"app_url": APP_URL, "admin_emails": sorted(ADMIN_EMAILS), "owner_emails": sorted(OWNER_EMAILS)}, owner_only=True)

@qr_app.post("/api/analyze")
async def api_analyze(request: Request, payload: dict = Body(...)):
    user = get_session_user(request)
    rate_limit = enforce_rate_limit(request, "analyze", 30, 60 * 60, user_key=user.get("google_id") if user else None)
    if rate_limit:
        return rate_limit
    validate_strict_payload(payload, {"url"})
    target_url = validate_public_url((payload.get("url") or "").strip())
    audit_log("qr.scanned", request=request, actor_user_id=user.get("google_id") if user else None, target_type="url", metadata={"url": target_url})
    return await analyze_full_pipeline(target_url)

@qr_app.post("/api/scan")
async def api_scan(request: Request, payload: dict = Body(...)):
    user = require_user(request)
    rate_limit = enforce_rate_limit(request, "scan", 30, 60 * 60, user_key=user.get("google_id"))
    if rate_limit:
        return rate_limit
    validate_strict_payload(payload, {"payload"})
    raw_payload = (payload.get("payload") or "").strip()
    if not raw_payload:
        raise SafeScanError("No QR payload supplied.", 400)
    if len(raw_payload) > 4096:
        raise SafeScanError("QR payload is too large.", 400)

    return await analyze_and_record_scan(request, user, raw_payload, request.headers.get("x-device-fingerprint", ""))

@qr_app.post("/api/scan/file")
async def api_scan_file(request: Request, file: UploadFile = File(...)):
    user = require_user(request)
    rate_limit = enforce_rate_limit(request, "scan_file", 30, 60 * 60, user_key=user.get("google_id"))
    if rate_limit:
        return rate_limit
    contents = await file.read()
    if len(contents) > MAX_QR_UPLOAD_BYTES:
        raise SafeScanError(f"Uploaded file is too large. Use a file under {MAX_QR_UPLOAD_BYTES // (1024 * 1024)} MB.", 400)

    persist_qr_upload(contents, file.filename, file.content_type, user)
    raw_payload, qr_image_for_ml = decode_qr_upload(contents, file.filename, file.content_type)
    if not raw_payload:
        raise SafeScanError("No QR code or valid payload detected in this file.", 400)

    try:
        return await analyze_and_record_scan(request, user, raw_payload, request.headers.get("x-device-fingerprint", ""), qr_image_for_ml)
    finally:
        if qr_image_for_ml is not None:
            qr_image_for_ml.close()

@qr_app.post("/api/qr/generate")
async def api_qr_generate(request: Request, payload: dict = Body(...)):
    """Generate a SafeScan-verified QR PNG for a URL.

    Runs the URL through the same risk pipeline as `/api/scan` and only
    renders the QR if the verdict is "safe". URLs flagged as suspicious or
    high-risk are refused — the whole point of the endpoint is that any QR
    coming out of it has been screened.

    Returns a PNG image with a small SafeScan badge overlaid in the centre
    (high error correction tolerates the badge without breaking scanning).
    """
    user = require_user(request)
    rate_limit = enforce_rate_limit(request, "qr_generate", 20, 60 * 60, user_key=user.get("google_id"))
    if rate_limit:
        return rate_limit

    validate_strict_payload(payload, {"url"})
    target_url = validate_public_url((payload.get("url") or "").strip())

    analysis = await analyze_full_pipeline(target_url)
    overall_risk = (analysis.get("overallRisk") or "").lower()
    verdict_text = analysis.get("verdict") or overall_risk or "unknown"

    if overall_risk == "high":
        raise SafeScanError(
            f"Refused to generate QR. SafeScan flagged this URL as dangerous ({verdict_text}).",
            400,
        )
    if overall_risk == "suspicious":
        raise SafeScanError(
            "Refused to generate QR. SafeScan flagged this URL as suspicious — review the scan report before publishing.",
            400,
        )

    # Lazy-imports keep boot-time fast for non-generator requests.
    import qrcode
    from qrcode.constants import ERROR_CORRECT_H
    from PIL import Image, ImageDraw

    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(target_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#03080f", back_color="white").convert("RGB")

    # Centre-overlay SafeScan badge. High error correction (~30% of modules)
    # tolerates this without breaking scanning.
    img_w, img_h = img.size
    badge_size = max(48, img_w // 5)
    bx = (img_w - badge_size) // 2
    by = (img_h - badge_size) // 2
    draw = ImageDraw.Draw(img)
    pad = 8
    draw.rectangle([bx - pad, by - pad, bx + badge_size + pad, by + badge_size + pad], fill="white")
    draw.rectangle([bx, by, bx + badge_size, by + badge_size], outline="#67f2c8", width=4)
    # Checkmark stroke.
    cx, cy = img_w // 2, img_h // 2
    s = badge_size // 3
    draw.line(
        [(cx - s // 2, cy + 2), (cx - s // 8, cy + s // 3), (cx + s // 2, cy - s // 3)],
        fill="#03080f",
        width=max(4, badge_size // 14),
    )

    buffer = io.BytesIO()
    img.save(buffer, format="PNG", optimize=True)
    png_bytes = buffer.getvalue()

    audit_log(
        "qr.generated",
        request=request,
        actor_user_id=user.get("google_id"),
        target_type="url",
        metadata={"url": target_url, "risk": overall_risk, "score": int(analysis.get("confidenceScore") or 0)},
    )

    return Response(
        content=png_bytes,
        media_type="image/png",
        headers={
            "X-SafeScan-Verdict": overall_risk or "safe",
            "X-SafeScan-Score": str(int(analysis.get("confidenceScore") or 0)),
            "Cache-Control": "no-store",
            "Content-Disposition": 'inline; filename="safescan-qr.png"',
        },
    )

async def analyze_and_record_scan(request, user, raw_payload, device_fingerprint="", qr_image_for_ml=None):
    if len(raw_payload) > 4096:
        raise SafeScanError("QR payload is too large.", 400)

    email = user["email"]
    verified_wallet = get_verified_wallet(email)
    wallet_address = verified_wallet["address"] if verified_wallet else ""
    payload_type, _, normalized_payload = detect_payload(raw_payload)

    if payload_type == "URL":
        try:
            analysis = await analyze_full_pipeline(normalized_payload, qr_image_for_ml)
        except SafeScanError as exc:
            analysis = {
                "url": normalized_payload,
                "overallRisk": "high",
                "confidenceScore": 95,
                "verdict": str(exc),
                "signals": [signal("URL Guard", "Blocked", "high", str(exc), False)],
                "actionDescription": describe_qr_action("URL", normalized_payload),
                "scannedAt": now_iso()
            }
        history_analysis = pipeline_response_to_template_analysis(analysis)
    else:
        embedded_urls = extract_urls(normalized_payload)
        if embedded_urls:
            try:
                history_analysis = await analyze_embedded_url_payload(raw_payload, embedded_urls[0], qr_image_for_ml)
            except SafeScanError:
                history_analysis = analyze_qr_payload(raw_payload)
        else:
            history_analysis = analyze_qr_payload(raw_payload)
        template_analysis = history_analysis
        history_analysis = template_analysis
        score = int(template_analysis.get("score") or 0)
        overall_risk = "high" if score >= 80 else ("suspicious" if score >= 40 else "safe")
        analysis = {
            "url": template_analysis["normalized"],
            "overallRisk": template_analysis.get("overallRisk", overall_risk),
            "confidenceScore": score,
            "verdict": template_analysis.get("verdict", template_analysis["threat_class"]),
            "actionDescription": template_analysis.get("action_description"),
            "signals": [
                signal(reason.get("label", "Payload Pattern"), template_analysis["status"], reason.get("severity", "low"), reason.get("detail", ""), score < 40)
                for reason in template_analysis.get("reasons", [])
            ],
            "virusTotal": template_analysis.get("virusTotal"),
            "domainAge": template_analysis.get("domainAge"),
            "mlRisk": template_analysis.get("mlRisk"),
            "ruleScore": template_analysis.get("ruleScore"),
            "scannedAt": now_iso(),
        }

    counted = record_unique_scan(email, raw_payload, wallet_address, user_id=user.get("google_id"))
    save_scan_history(email, history_analysis["normalized"], history_analysis, user_id=user.get("google_id"))
    run_fraud_checks("scan", email, request, {"url": history_analysis["normalized"], "deviceFingerprint": device_fingerprint})
    audit_log("qr.scanned", request=request, actor_user_id=user.get("google_id"), target_type="scan", metadata={"counted": counted, "payloadType": payload_type})
    return {
        **analysis,
        "actionDescription": analysis.get("actionDescription") or history_analysis.get("action_description"),
        "counted": counted,
        "scanCount": get_scan_count(email),
        "payloadType": payload_type,
    }

@qr_app.get("/api/scan-history")
@qr_app.get("/api/scan/history")
async def api_scan_history(request: Request):
    require_user(request)
    try:
        limit = int(request.query_params.get("limit", "50"))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 100))

    with get_conn() as conn:
        rows = user_scoped_select(conn, "scan_history")
    rows = sorted(rows, key=lambda row: row["created_at"] or "", reverse=True)[:limit]

    history = []
    for row in rows:
        try:
            signals = json.loads(row["signals"] or "[]")
        except (TypeError, json.JSONDecodeError):
            signals = []
        history.append({
            "scanId": row["id"],
            "id": row["id"],
            "url": row["url"],
            "verdict": row["verdict"] or "safe",
            "riskScore": int(row["risk_score"] or 0),
            "signals": signals if isinstance(signals, list) else [],
            "reported": bool(row["reported"]),
            "analyzedAt": row["created_at"],
            "scannedAt": row["created_at"],
        })
    return history

@qr_app.get("/api/history")
async def api_history(request: Request):
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    with get_conn() as conn:
        rows = user_scoped_select(conn, "scan_history")
    rows = sorted(rows, key=lambda row: row["created_at"] or "", reverse=True)[:100]
    result = []
    for row in rows:
        try:
            signals = json.loads(row["signals"] or "[]")
        except (TypeError, json.JSONDecodeError):
            signals = []
        result.append({
            "scanId": row["id"],
            "id": row["id"],
            "url": row["url"],
            "verdict": row["verdict"] or "safe",
            "threat_type": row["verdict"] or "safe",
            "riskScore": int(row["risk_score"] or 0),
            "risk_score": int(row["risk_score"] or 0),
            "signals": signals if isinstance(signals, list) else [],
            "reported": bool(row["reported"]),
            "scannedAt": row["created_at"],
            "analyzedAt": row["created_at"],
        })
    return result

@qr_app.get("/api/app-runtime")
async def api_app_runtime():
    now = datetime.utcnow()
    return {
        "startedAt": APP_STARTED_AT.isoformat() + "Z",
        "serverNow": now.isoformat() + "Z",
        "uptimeSeconds": int((now - APP_STARTED_AT).total_seconds()),
    }

@qr_app.post("/api/report")
async def api_report_url(request: Request, payload: dict = Body(...)):
    user = get_session_user(request)
    rate_limit = enforce_rate_limit(request, "report", 10, 60 * 60, user_key=user.get("google_id") if user else None)
    if rate_limit:
        return rate_limit
    validate_strict_payload(payload, {"url", "reason"})
    reason = payload.get("reason")
    if reason not in ("phishing", "wallet_drain", "malware", "spam", "other"):
        raise SafeScanError("Invalid report reason.", 400)
    target_url = validate_public_url(payload.get("url", ""))
    analysis = await analyze_full_pipeline(target_url)
    report_id = make_id("report")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO url_reports VALUES (?, ?, ?, ?, ?, 'pending', ?, NULL, NULL)",
            (report_id, target_url, user.get("email") if user else "", reason, int(analysis.get("confidenceScore") or 0), now_iso())
        )
    audit_log("url.reported", request=request, actor_user_id=user.get("google_id") if user else None, target_type="url_report", target_id=report_id, metadata={"reason": reason, "url": target_url})
    return {"id": report_id, "status": "pending"}

@qr_app.get("/api/user/profile")
async def api_user_profile(request: Request):
    user = require_user(request)
    email = user["email"]
    scan_count = get_scan_count(email)
    with get_conn() as conn:
        referral_count = conn.execute("SELECT COUNT(*) FROM referrals WHERE referrer_email = ? AND counted = 1", (email,)).fetchone()[0]
    wallet = get_verified_wallet(email)
    return {
        "id": user.get("google_id"),
        "name": "Safe scanner",
        "email": email,
        "role": user.get("role", "user"),
        "scanCount": scan_count,
        "referrals": referral_count,
        "tier": airdrop_tier(scan_count, referral_count),
        "walletConnected": bool(wallet),
    }

@qr_app.get("/api/me")
async def api_me(request: Request):
    user = require_user(request)
    return {
        "session": {"id": user.get("session_id")},
        "user": {
            "id": user.get("google_id"),
            "email": user.get("email"),
            "username": user.get("username"),
            "name": user.get("display_name") or "Safe scanner",
            "avatarUrl": user.get("picture"),
            "role": user.get("role", "user"),
            "status": user.get("status", "active"),
        },
    }

@qr_app.get("/api/scans")
async def api_scans(request: Request):
    require_user(request)
    with get_conn() as conn:
        scans = [dict(row) for row in user_scoped_select(conn, "scans")]
        events = [dict(row) for row in user_scoped_select(conn, "scan_events")]
    return {"scans": scans, "events": events}

@qr_app.get("/api/referral")
async def api_referral_status(request: Request):
    user = require_user(request)
    email = user["email"]
    code = referral_code_for_user(email)
    with get_conn() as conn:
        referral_count = conn.execute("SELECT COUNT(*) FROM referrals WHERE referrer_email = ? AND counted = 1", (email,)).fetchone()[0]
    return {
        "code": code,
        "link": f"{APP_URL}/?ref={code}",
        "referrals": referral_count,
    }

@qr_app.get("/api/airdrop/status")
async def api_airdrop_status(request: Request):
    user = require_user(request)
    email = user["email"]
    scan_count = get_scan_count(email)
    with get_conn() as conn:
        row = conn.execute("SELECT airdrop_status, COALESCE(fraud_score, 0), referral_code FROM users WHERE email = ?", (email,)).fetchone()
        referrals = conn.execute("SELECT COUNT(*) FROM referrals WHERE referrer_email = ? AND counted = 1", (email,)).fetchone()[0]
    referral_code = row[2] if row and row[2] else referral_code_for_user(email)
    wallet = get_verified_wallet(email)
    current_tier = airdrop_tier(scan_count, referrals)
    return {
        "scanCount": scan_count,
        "referrals": referrals,
        "currentTier": current_tier,
        "walletConnected": bool(wallet),
        "walletAddress": wallet.get("address") if wallet else None,
        "airdropStatus": row[0] if row else "eligible",
        "fraudScore": int(row[1]) if row else 0,
        "referralCode": referral_code,
        "referralLink": f"{APP_URL}/?ref={referral_code}" if referral_code else None,
        "nextMilestone": next_airdrop_milestone(scan_count, referrals),
    }

@qr_app.get("/api/wallet")
async def api_wallet_status(request: Request):
    user = require_user(request)
    wallet = get_verified_wallet(user["email"])
    if not wallet:
        return {"connected": False}
    return {
        "connected": True,
        "walletAddress": wallet["address"],
        "verified": bool(wallet["verified"]),
        "connectedAt": wallet["connected_at"],
        "onchain": {
            "solBalance": wallet.get("sol_balance"),
            "txCount": wallet.get("tx_count"),
            "walletAgeDays": wallet.get("wallet_age_days"),
            "verifiedAt": wallet.get("onchain_verified_at"),
        },
    }

@qr_app.post("/api/wallet/nonce")
async def api_wallet_nonce(request: Request, payload: dict = Body(...)):
    user = require_user(request)
    cleanup_wallet_nonces()
    validate_strict_payload(payload, {"walletAddress"})
    wallet_address = (payload.get("walletAddress") or "").strip()
    if not is_valid_solana_address(wallet_address):
        raise SafeScanError("Invalid Solana address format.", 400)
    rate_limit = enforce_rate_limit(request, "wallet_nonce", 5, 60 * 60, user_key=wallet_address.lower())
    if rate_limit:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO fraud_flags VALUES (?, ?, 'wallet_nonce_rate_limit', 'medium', ?, ?, 0, 0, NULL, NULL, NULL, ?)",
                (
                    make_id("fraud"),
                    user["email"],
                    "Too many wallet verification challenges requested for one wallet.",
                    json.dumps({"walletAddress": wallet_address[:8] + "..."}),
                    now_iso(),
                )
            )
            conn.execute(
                "UPDATE users SET fraud_score = COALESCE(fraud_score, 0) + 20, airdrop_status = 'flagged' WHERE email = ?",
                (user["email"],)
            )
        return rate_limit
    with get_conn() as conn:
        existing = conn.execute(
            """
            SELECT user_id FROM wallets WHERE address = ? AND user_id != ? AND verified = 1
            UNION
            SELECT email FROM scans WHERE wallet_address = ? AND email != ?
            LIMIT 1
            """,
            (wallet_address, user["email"], wallet_address, user["email"])
        ).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="This wallet is already linked to another account.")
    nonce = secrets.token_hex(32)
    issued_at = now_iso()
    expires_at = (datetime.utcnow() + timedelta(minutes=5)).isoformat() + "Z"
    message = wallet_verification_message(nonce, user["email"], issued_at, expires_at)
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO wallet_nonces (user_id, wallet_address, nonce, message, issued_at, expires_at, used, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              wallet_address=excluded.wallet_address,
              nonce=excluded.nonce,
              message=excluded.message,
              issued_at=excluded.issued_at,
              expires_at=excluded.expires_at,
              used=0,
              created_at=excluded.created_at
            """,
            (user["email"], wallet_address, nonce, message, issued_at, expires_at, issued_at)
        )
    audit_log("wallet.nonce_issued", request=request, actor_user_id=user.get("google_id"), target_type="wallet", target_id=wallet_address[:8] + "...")
    return {"nonce": nonce, "message": message, "expiresAt": expires_at}

@qr_app.post("/api/wallet/verify")
async def api_wallet_verify(request: Request, payload: dict = Body(...)):
    user = require_user(request)
    cleanup_wallet_nonces()
    validate_strict_payload(payload, {"walletAddress", "signature"})
    wallet_address = (payload.get("walletAddress") or "").strip()
    signature = (payload.get("signature") or "").strip()
    if not is_valid_solana_address(wallet_address):
        raise SafeScanError("Invalid Solana address format.", 400)
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        stored = conn.execute(
            "SELECT * FROM wallet_nonces WHERE user_id = ? AND wallet_address = ? AND used = 0",
            (user["email"], wallet_address)
        ).fetchone()
    if not stored:
        raise SafeScanError("No pending verification for this wallet.", 400)
    try:
        issued_at = datetime.fromisoformat(str(stored["issued_at"]).replace("Z", ""))
        expires_at = datetime.fromisoformat(str(stored["expires_at"]).replace("Z", ""))
    except ValueError:
        raise SafeScanError("Verification expired. Please try again.", 400)
    if datetime.utcnow() > expires_at or datetime.utcnow() - issued_at > timedelta(minutes=5):
        with get_conn() as conn:
            conn.execute("DELETE FROM wallet_nonces WHERE user_id = ?", (user["email"],))
        raise SafeScanError("Verification expired. Please try again.", 400)
    message = wallet_verification_message(stored["nonce"], user["email"], stored["issued_at"], stored["expires_at"])
    try:
        verify_solana_signature(wallet_address, signature, message)
    except (ValueError, InvalidSignature):
        with get_conn() as conn:
            conn.execute("UPDATE wallet_nonces SET used = 1 WHERE user_id = ?", (user["email"],))
        audit_log(
            "wallet.verification_failed",
            request=request,
            actor_user_id=user.get("google_id"),
            target_type="wallet",
            target_id=wallet_address[:8] + "...",
            metadata={"reason": "signature_invalid"}
        )
        raise SafeScanError("Signature verification failed. Request a new challenge and try again.", 400)
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT user_id FROM wallets WHERE address = ? AND user_id != ? AND verified = 1 LIMIT 1",
            (wallet_address, user["email"])
        ).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="This wallet is already linked to another account.")
    signals = run_fraud_checks(
        "wallet_connect",
        user["email"],
        request,
        {"walletAddress": wallet_address, "deviceFingerprint": request.headers.get("x-device-fingerprint", "")}
    )
    if any(signal.get("autoDisqualify") for signal in signals):
        raise HTTPException(status_code=403, detail="Wallet connection could not be completed. Contact support.")
    connected_at = now_iso()
    with get_conn() as conn:
        conn.execute("UPDATE wallet_nonces SET used = 1 WHERE user_id = ?", (user["email"],))
        conn.execute(
            """
            INSERT INTO wallets (id, user_id, address, verified, connected_at, disconnected_at)
            VALUES (?, ?, ?, 1, ?, NULL)
            ON CONFLICT(user_id) DO UPDATE SET
              address=excluded.address,
              verified=1,
              connected_at=excluded.connected_at,
              disconnected_at=NULL
            """,
            (make_id("wallet"), user["email"], wallet_address, connected_at)
        )
        conn.execute(
            """
            INSERT INTO scans (email, wallet_address)
            VALUES (?, ?)
            ON CONFLICT(email) DO UPDATE SET wallet_address=excluded.wallet_address
            """,
            (user["email"], wallet_address)
        )
    audit_log("wallet.connected", request=request, actor_user_id=user.get("google_id"), target_type="wallet", target_id=wallet_address[:8] + "...")
    asyncio.create_task(verify_wallet_on_chain(wallet_address, user["email"]))
    return {"success": True, "walletAddress": wallet_address, "verified": True, "connectedAt": connected_at}

@qr_app.delete("/api/wallet")
async def api_wallet_disconnect(request: Request):
    user = require_user(request)
    wallet = get_verified_wallet(user["email"])
    if not wallet:
        raise HTTPException(status_code=404, detail="No connected wallet found.")
    with get_conn() as conn:
        conn.execute("DELETE FROM wallets WHERE user_id = ?", (user["email"],))
        conn.execute("DELETE FROM wallet_nonces WHERE user_id = ?", (user["email"],))
        conn.execute("UPDATE scans SET wallet_address = NULL WHERE email = ?", (user["email"],))
    audit_log("wallet.disconnected", request=request, actor_user_id=user.get("google_id"), target_type="wallet", target_id=wallet["address"][:8] + "...")
    return {"success": True, "message": "Wallet disconnected successfully"}

@qr_app.get("/api/admin/stats/users")
async def api_admin_stats_users(request: Request):
    require_role_user(request, "admin")
    with get_conn() as conn:
        value = conn.execute("SELECT COUNT(*) FROM users WHERE status != 'deleted'").fetchone()[0]
    return {"value": value}

@qr_app.get("/api/admin/stats/scans-today")
async def api_admin_stats_scans_today(request: Request):
    require_role_user(request, "admin")
    with get_conn() as conn:
        value = conn.execute("SELECT COUNT(*) FROM scan_history WHERE created_at >= ?", (datetime.utcnow().date().isoformat(),)).fetchone()[0]
    return {"value": value}

@qr_app.get("/api/admin/stats/blocked")
async def api_admin_stats_blocked(request: Request):
    require_role_user(request, "admin")
    with get_conn() as conn:
        value = conn.execute("SELECT COUNT(*) FROM scan_history WHERE verdict IN ('MALICIOUS', 'HIGH') OR risk_score >= 80").fetchone()[0]
    return {"value": value}

@qr_app.get("/api/admin/stats/fraud-flags")
async def api_admin_stats_fraud_flags(request: Request):
    require_role_user(request, "admin")
    with get_conn() as conn:
        value = len(user_scoped_select(conn, "fraud_flags", "reviewed = 0"))
    return {"value": value}

@qr_app.get("/api/fraud-flags")
async def api_fraud_flags(request: Request):
    require_role_user(request, "admin")
    with get_conn() as conn:
        rows = [dict(row) for row in user_scoped_select(conn, "fraud_flags", "reviewed = 0")]
    return {"rows": rows}

@qr_app.post("/api/check-reputation")
async def api_check_reputation(payload: dict = Body(...)):
    validate_strict_payload(payload, {"url"})
    normalized = validate_public_url((payload.get("url") or "").strip())
    google_task = asyncio.to_thread(google_reputation_signal, normalized)
    virustotal_task = asyncio.to_thread(virustotal_reputation_signal, normalized)
    results = await asyncio.gather(google_task, virustotal_task)
    return {"url": normalized, "signals": list(results), "scannedAt": datetime.utcnow().isoformat() + "Z"}

@qr_app.post("/api/trace-redirects")
async def api_trace_redirects(payload: dict = Body(...)):
    validate_strict_payload(payload, {"url"})
    normalized = validate_public_url((payload.get("url") or "").strip())
    result = await asyncio.to_thread(trace_redirect_chain, normalized)
    return {"url": normalized, **result, "scannedAt": datetime.utcnow().isoformat() + "Z"}

@qr_app.post("/api/check-domain")
async def api_check_domain(payload: dict = Body(...)):
    validate_strict_payload(payload, {"url"})
    normalized = validate_public_url((payload.get("url") or "").strip())
    signals = await asyncio.to_thread(check_domain_intelligence, normalized)
    return {"url": normalized, "signals": signals, "scannedAt": datetime.utcnow().isoformat() + "Z"}

@qr_app.post("/api/check-crypto-patterns")
async def api_check_crypto_patterns(payload: dict = Body(...)):
    validate_strict_payload(payload, {"url"})
    normalized = validate_public_url((payload.get("url") or "").strip())
    signals = await asyncio.to_thread(check_crypto_pattern_signals, normalized)
    return {"url": normalized, "signals": signals, "scannedAt": datetime.utcnow().isoformat() + "Z"}

@qr_app.get("/", response_class=HTMLResponse)
async def read_index(request: Request):
    user = get_session_user(request)
    email = user["email"] if user else ""
    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": bool(user), "results_visible": False, "google_client_id": CLIENT_ID,
        "email": email, "scan_count": get_scan_count(email) if email else 0,
        "test_site": True,
        "test_site_path": False,
        "version": LEGAL_VERSION,
        **index_user_context(user)
    })

@qr_app.get("/test-site", response_class=HTMLResponse)
async def read_test_site(request: Request):
    user = get_session_user(request)
    email = user["email"] if user else ""
    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": bool(user), "results_visible": False, "google_client_id": CLIENT_ID,
        "email": email, "scan_count": get_scan_count(email) if email else 0,
        "test_site": True,
        "test_site_path": True,
        "version": LEGAL_VERSION,
        **index_user_context(user)
    })

@qr_app.get("/go-ghost", response_class=HTMLResponse)
async def go_ghost_page(request: Request):
    user = get_session_user(request)
    return templates.TemplateResponse("go_ghost.html", {
        "request": request,
        "logged_in": bool(user),
        "email": user["email"] if user else "",
        "version": LEGAL_VERSION,
        **index_user_context(user),
    })

@qr_app.post("/api/go-ghost/removals/{broker}")
async def api_go_ghost_removal(request: Request, broker: str, payload: dict = Body(...)):
    user = require_user(request)
    normalized_broker = (broker or "").strip().lower()
    if normalized_broker != "fastpeoplesearch":
        raise SafeScanError("Backend automation is available for FastPeopleSearch first.", 400)
    validate_strict_payload(payload, {"name", "address", "cityState", "phone", "email"})

    profile_payload = {
        "name": str(payload.get("name") or "").strip()[:160],
        "address": str(payload.get("address") or "").strip()[:220],
        "city_state": str(payload.get("cityState") or "").strip()[:140],
        "phone": str(payload.get("phone") or "").strip()[:80],
        "email": str(payload.get("email") or "").strip()[:180],
    }
    if not profile_payload["name"]:
        raise SafeScanError("Add a full name before running automation.", 400)
    if not profile_payload["email"]:
        raise SafeScanError("Add an email before running automation.", 400)

    job_id = make_id("ghostjob")
    account_email = (user.get("email") or "").strip().lower()
    created_at = now_iso()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO go_ghost_removal_jobs
               (id, user_id, email, broker, status, detail, target_url, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                job_id,
                user.get("google_id"),
                account_email,
                normalized_broker,
                "running",
                "Automation started.",
                "https://www.fastpeoplesearch.com/optout",
                created_at,
                created_at,
            ),
        )

    try:
        from removals.engine import RemovalProfile, run_fastpeoplesearch_removal

        result = await run_fastpeoplesearch_removal(RemovalProfile(**profile_payload))
    except RuntimeError as exc:
        result = {
            "status": "unavailable",
            "detail": str(exc),
            "targetUrl": "https://www.fastpeoplesearch.com/optout",
        }
    except Exception:
        result = {
            "status": "failed",
            "detail": "FastPeopleSearch automation failed before submission.",
            "targetUrl": "https://www.fastpeoplesearch.com/optout",
        }

    status = str(result.get("status") or "failed")[:40]
    detail = str(result.get("detail") or "")[:500]
    target_url = str(result.get("targetUrl") or "https://www.fastpeoplesearch.com/optout")[:500]
    with get_conn() as conn:
        conn.execute(
            """UPDATE go_ghost_removal_jobs
               SET status = ?, detail = ?, target_url = ?, updated_at = ?
               WHERE id = ?""",
            (status, detail, target_url, now_iso(), job_id),
        )

    audit_log(
        "go_ghost.removal_attempted",
        request=request,
        actor_user_id=user.get("google_id"),
        target_type="broker",
        target_id=normalized_broker,
        metadata={"jobId": job_id, "status": status},
    )
    return {"jobId": job_id, "broker": normalized_broker, "status": status, "detail": detail, "targetUrl": target_url}

@qr_app.get("/legal/privacy-policy", response_class=HTMLResponse)
async def privacy_policy(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Privacy Policy", PRIVACY_POLICY_HTML))

@qr_app.post("/waitlist", response_class=HTMLResponse)
async def waitlist_signup(request: Request, email: str = Form(...)):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO waitlist_signups VALUES (?, ?, ?)",
            (email.strip().lower(), "footer", datetime.utcnow().isoformat() + "Z")
        )
    body = "<h2>You're on the list</h2><p>Thanks for joining the SafeScan QR waitlist. We'll send only major product updates.</p><p><a href='/'>Return to SafeScan QR</a></p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Waitlist", body))

@qr_app.get("/legal/terms-of-use", response_class=HTMLResponse)
async def terms_of_use(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Terms of Use", TERMS_HTML))

@qr_app.get("/legal/cookie-policy", response_class=HTMLResponse)
async def cookie_policy(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Cookie Policy", COOKIE_POLICY_HTML))

@qr_app.get("/legal/terms-history", response_class=HTMLResponse)
async def terms_history(request: Request):
    body = "<h2>Version History</h2><p>v1.0 - May 2026: Initial SafeScan QR Terms of Use.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Terms History", body))

@qr_app.get("/changelog", response_class=HTMLResponse)
async def changelog_page(request: Request):
    body = "<h2>Changelog</h2><p>v0.1 - May 2026: SafeScan QR hackathon MVP, risk engine, legal pages, and footer system.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Changelog", body))

@qr_app.get("/legal/license", response_class=HTMLResponse)
async def license_page(request: Request):
    body = """
    <h2>License</h2>
    <p>SafeScan QR is currently proprietary while the product is in hackathon and early beta development. Open-source components remain governed by their original licenses.</p>
    <p>Public API, SDK, and mobile client licensing will be published before a production developer release.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "License", body))

@qr_app.get("/legal/security", response_class=HTMLResponse)
async def security_page(request: Request):
    body = f"""
    <h2>Security</h2>
    <p>SafeScan QR analyzes QR payloads, URLs, wallet links, redirect chains, reputation signals, and crypto-specific risk patterns before users continue.</p>
    <p>To report a vulnerability, contact <a href="mailto:{ADMIN_EMAIL}">{ADMIN_EMAIL}</a>. Please include affected routes, reproduction steps, and potential impact.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Security", body))

@qr_app.get("/contact", response_class=HTMLResponse)
async def contact_page(request: Request):
    body = f"""
    <section class="contact-hero">
      <h2>Contact SafeScan QR</h2>
      <p>For community updates, support, security reports, partnerships, or privacy questions, use the best channel below.</p>
    </section>

    <div class="contact-grid">
      <a class="contact-card contact-card-primary" href="https://discord.gg/hqHBQ22z" target="_blank" rel="noopener noreferrer">
        <span class="contact-label">Community</span>
        <strong>Join the Discord</strong>
        <p>Ask questions, follow release updates, and connect with the SafeScan QR community.</p>
      </a>
      <a class="contact-card" href="{ADMIN_EMAIL_GMAIL_COMPOSE_URL}" target="_blank" rel="noopener noreferrer">
        <span class="contact-label">Email</span>
        <strong>{ADMIN_EMAIL}</strong>
        <p>Best for account, privacy, partnership, and general support questions.</p>
      </a>
      <a class="contact-card" href="/legal/security">
        <span class="contact-label">Security</span>
        <strong>Report a vulnerability</strong>
        <p>Send affected routes, reproduction steps, and potential impact so we can investigate quickly.</p>
      </a>
      <a class="contact-card" href="https://github.com/Sammy12357/SafeScan-QR" target="_blank" rel="noopener noreferrer">
        <span class="contact-label">Code</span>
        <strong>GitHub</strong>
        <p>View the project repository and track public development.</p>
      </a>
    </div>

    <p class="contact-note">For privacy rights requests, use the <a href="/legal/data-request">Data Request portal</a>. For sale/sharing opt-outs, use <a href="/legal/do-not-sell">Do Not Sell or Share</a>.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Contact", body))

@qr_app.get("/product/install", response_class=HTMLResponse)
async def product_install(request: Request):
    body = "<h2>Install</h2><p>SafeScan QR is currently available as a web demo. iOS, Android, and Solana Mobile distribution are planned after the hackathon MVP.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Install", body))

@qr_app.get("/product/getting-started", response_class=HTMLResponse)
async def product_getting_started(request: Request):
    body = "<h2>Getting Started</h2><p>Sign in, connect a wallet for airdrop tracking, then scan or paste a QR payload to see the SafeScan risk verdict and signal breakdown.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Getting Started", body))

@qr_app.get("/risk-engine", response_class=HTMLResponse)
async def risk_engine_page(request: Request):
    body = """
    <h2>Risk analysis model</h2>
    <p>SafeScan QR turns a QR payload into a 0-100 risk score by decoding the payload, classifying the action, inspecting URLs, checking reputation sources, matching wallet-drain patterns, and optionally blending in the local ML model. The final verdict is informational, not a guarantee of safety.</p>

    <div class="risk-model-grid">
      <section>
        <h3>Score bands</h3>
        <ul>
          <li><strong>0-39 SAFE:</strong> no major suspicious indicators were found.</li>
          <li><strong>40-79 CAUTION:</strong> one or more suspicious signals need review.</li>
          <li><strong>80-100 MALICIOUS:</strong> high-risk signals indicate likely phishing, malware, credential theft, or wallet drain behavior.</li>
        </ul>
      </section>
      <section>
        <h3>Output data</h3>
        <ul>
          <li>Final verdict, risk score, confidence score, and threat class.</li>
          <li>Decoded URL or non-URL QR payload.</li>
          <li>Human-readable explanation and next-action guidance.</li>
          <li>Signal list with label, severity, detail, and whether the signal is positive or negative.</li>
        </ul>
      </section>
    </div>

    <h2>Data checked during analysis</h2>
    <div class="risk-model-grid">
      <section>
        <h3>Payload and action data</h3>
        <ul>
          <li>URL, text, Wi-Fi, email, SMS, phone, contact card, calendar, wallet, payment, and app-deep-link payloads.</li>
          <li>Embedded URLs hidden inside non-URL QR actions.</li>
          <li>Sensitive wording such as password, seed, recovery, verify, login, wallet, bank, and urgent.</li>
          <li>Download, installer, executable, and compressed file paths.</li>
        </ul>
      </section>
      <section>
        <h3>URL and domain data</h3>
        <ul>
          <li>HTTPS vs non-HTTPS destination.</li>
          <li>Hostname, top-level domain, punycode, suspicious query parameters, fragments, and redirects.</li>
          <li>Domain age from WHOIS/RDAP when available.</li>
          <li>New, recently registered, unknown-age, and high-risk TLD indicators.</li>
        </ul>
      </section>
      <section>
        <h3>Reputation data</h3>
        <ul>
          <li>Google Safe Browsing threat matches when the API key is configured.</li>
          <li>VirusTotal-style engine summary: clean, unrated, malicious, and suspicious vendor results.</li>
          <li>Local URL cache so repeated scans can reuse recent verdicts quickly.</li>
          <li>Admin-confirmed reports and blocklist decisions.</li>
        </ul>
      </section>
      <section>
        <h3>Crypto and payment data</h3>
        <ul>
          <li>Solana and wallet-deep-link payloads.</li>
          <li>Wallet address placement in URL query strings or fragments.</li>
          <li>Claim, approve, permit, signature, drain, mint, airdrop, and connect-wallet language.</li>
          <li>Payment QR actions that can launch wallet, transfer, or checkout flows.</li>
        </ul>
      </section>
    </div>

    <h2>Model pipeline</h2>
    <ol>
      <li><strong>Decode:</strong> read the QR image, pasted payload, SVG, PDF, or manual URL input.</li>
      <li><strong>Normalize:</strong> trim and classify the payload type, extract embedded URLs, and validate URL shape.</li>
      <li><strong>Inspect:</strong> check scheme, domain, path, query, redirects, reputation matches, domain age, and crypto patterns.</li>
      <li><strong>Score:</strong> convert each signal into weighted risk, then clamp the final confidence score from 0 to 100.</li>
      <li><strong>Blend ML:</strong> when enabled, combine the local QR ML model score with rule-based evidence.</li>
      <li><strong>Explain:</strong> return the verdict, score, reasons, action description, threat class, and optional admin/reporting metadata.</li>
    </ol>

    <h2>Stored data</h2>
    <p>For signed-in users, SafeScan can save scan history and counters so profile progress, scan history, fraud prevention, and leaderboard features work across sessions. Stored scan rows may include user id, email, URL or payload, risk score, verdict, signal JSON, report status, and created time. Uploaded QR image files may be stored temporarily according to the configured upload retention policy.</p>

    <h2>Privacy and limits</h2>
    <p>SafeScan avoids sending direct personal identifiers to external AI analysis providers. URL payloads and risk signals may be processed by configured reputation or AI services. The engine is designed to explain risk clearly, but users should still verify important links, wallet prompts, and payment requests independently.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Risk Engine", body))

@qr_app.get("/product/wedges", response_class=HTMLResponse)
async def product_wedges(request: Request):
    body = "<h2>Wedges</h2><p>SafeScan starts with consumer QR safety, expands into Solana Mobile distribution, and grows into a threat-intelligence API for wallets, dApps, and payment providers.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Wedges", body))

@qr_app.get("/product/pricing", response_class=HTMLResponse)
async def product_pricing(request: Request):
    body = "<h2>Pricing</h2><p>The SafeScan QR public demo is free during the hackathon. Alpha premium access is $1/mo for early API docs, endpoint access, and merchant QR safety workflows.</p><p><a class='primary-button' href='/pay/alpha'>Pay Now</a></p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Pricing", body))

@qr_app.get("/pay/alpha", response_class=HTMLResponse)
async def alpha_payment_page(request: Request):
    stripe_url = alpha_stripe_checkout_url(request)
    stripe_button = (
        f"<a class='primary-button payment-button' href='{stripe_url}' rel='noopener noreferrer'>Pay by card with Stripe</a>"
        if stripe_url else
        "<span class='secondary-button payment-button payment-disabled'>Stripe checkout not configured</span>"
    )
    solana_url = alpha_solana_pay_url()
    solana_button = (
        f"<a class='secondary-button payment-button' href='{solana_url}'>Pay with Solana</a>"
        if solana_url else
        "<span class='secondary-button payment-button payment-disabled'>Solana Pay not configured</span>"
    )
    solana_note = (
        f"<p class='payment-note'>Solana payment recipient: <code>{ALPHA_SOLANA_RECIPIENT}</code></p>"
        if ALPHA_SOLANA_RECIPIENT else
        "<p class='payment-note'>Add ALPHA_SOLANA_RECIPIENT in Render to enable wallet checkout.</p>"
    )
    body = f"""
    <h2>Alpha Premium</h2>
    <p>Pay $1/mo for Alpha access to SafeScan QR premium API docs, risk scoring endpoints, and merchant QR safety workflows.</p>
    <div class="payment-panel">
      <div class="payment-option">
        <p class="eyebrow">Card</p>
        <h3>Stripe checkout</h3>
        <p>Use this for credit card and subscription billing.</p>
        {stripe_button}
      </div>
      <div class="payment-option payment-option-wallet">
        <h3>Wallet payment</h3>
        <p>Use this for a Solana Pay transfer. Access approval still needs manual or webhook confirmation.</p>
        {solana_button}
        {solana_note}
      </div>
    </div>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Alpha Payment", body))

@qr_app.get("/pay/alpha/success", response_class=HTMLResponse)
async def alpha_payment_success_page(request: Request):
    recorded_purchase = record_alpha_subscription_purchase(request)
    storage_note = (
        f"<p class='payment-note'>Subscription start saved for {recorded_purchase['email']} on {recorded_purchase['purchased_at']}.</p>"
        if recorded_purchase else
        "<p class='payment-note'>Sign in to SafeScan, then revisit this success page so your subscription start date can be saved to your account.</p>"
    )
    body = f"""
    <h2>Alpha payment received</h2>
    <p>Thanks for subscribing to SafeScan Alpha Premium. Your payment processor has accepted the checkout session.</p>
    <div class="payment-panel">
      <div>
        <p class="eyebrow">Next step</p>
        <h3>Activate access</h3>
        <p>Email your Stripe receipt or Solana transaction signature to <a href="mailto:{ADMIN_EMAIL}">{ADMIN_EMAIL}</a>. Include the email you use to sign in to SafeScan.</p>
      </div>
      <div>
        <p class="eyebrow">Alpha docs</p>
        <h3>Continue to docs</h3>
        <p>Review the current Alpha docs while access is activated.</p>
        <a class="primary-button payment-button" href="/resources/docs">Open docs</a>
      </div>
    </div>
    {storage_note}
    <p class="payment-note">For fully automatic Stripe verification, connect a Stripe webhook next so SafeScan can confirm paid checkout sessions directly from Stripe.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Alpha Payment Success", body))

@qr_app.get("/resources/docs", response_class=HTMLResponse)
async def resources_docs(request: Request):
    body = "<h2>Docs</h2><p>SafeScan docs will cover QR scanning, risk signals, reputation checks, wallet-pattern detection, and API usage.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Docs", body))

@qr_app.get("/resources/architecture", response_class=HTMLResponse)
async def resources_architecture(request: Request):
    body = "<h2>Architecture</h2><p>The risk engine pipeline normalizes QR payloads, checks domain intelligence, traces redirects, runs reputation lookups, matches crypto risk patterns, and merges signals into a verdict.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Architecture", body))

@qr_app.get("/resources/roadmap", response_class=HTMLResponse)
async def resources_roadmap(request: Request):
    body = "<h2>Roadmap</h2><p>Next milestones: waitlist, mobile beta, Solana dApp Store submission, wallet integrations, threat-intelligence API, and expanded abuse reporting.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Roadmap", body))

@qr_app.get("/tokenomics", response_class=HTMLResponse)
async def tokenomics_page(request: Request):
    body = """
    <h2>$SQR SafeScan Token Whitepaper</h2>
    <p>$SQR is the proposed utility token for the SafeScan QR ecosystem. It is designed to support QR threat intelligence, wallet safety workflows, merchant integrations, community reporting, and access to advanced security features. This page is informational and does not offer financial, investment, tax, or legal advice.</p>

    <h2>Mission</h2>
    <p>SafeScan exists to make QR codes, wallet prompts, payment links, and app-deep-link actions understandable before a user continues. $SQR is intended to align the product, security contributors, integration partners, and active users around safer scan-before-you-sign behavior.</p>

    <div class="risk-model-grid">
      <section>
        <h3>Network role</h3>
        <ul>
          <li>Support access to advanced QR risk intelligence features.</li>
          <li>Power future merchant and developer API workflows.</li>
          <li>Reward useful security participation, verified reports, and ecosystem contribution.</li>
          <li>Create a shared identity layer for SafeScan-aligned security tooling.</li>
        </ul>
      </section>
      <section>
        <h3>Product utility</h3>
        <ul>
          <li>Risk scan credits for higher-volume API or merchant usage.</li>
          <li>Access controls for premium intelligence endpoints.</li>
          <li>Reputation markers for trusted reporters, merchants, and integrations.</li>
          <li>Governance-style feedback on product priorities where legally appropriate.</li>
        </ul>
      </section>
    </div>

    <h2>Supply framework</h2>
    <p>The $SQR supply framework is intended to be fixed, transparent, and published before any production token event. Allocation categories may include ecosystem growth, product development, security operations, liquidity support, treasury reserves, partnerships, and community participation. Final numbers should be published only after legal, tax, and launch review.</p>

    <h2>Ecosystem participants</h2>
    <div class="risk-model-grid">
      <section>
        <h3>Users</h3>
        <ul>
          <li>Scan suspicious QR codes before opening links or wallet prompts.</li>
          <li>Review the risk explanation and report malicious payloads.</li>
          <li>Build a portable SafeScan security profile over time.</li>
        </ul>
      </section>
      <section>
        <h3>Merchants and builders</h3>
        <ul>
          <li>Use SafeScan APIs to pre-check payment QR codes and customer-facing links.</li>
          <li>Integrate risk labels into checkout, wallet, event, and campaign flows.</li>
          <li>Use SafeScan reputation data to reduce spoofing and brand impersonation.</li>
        </ul>
      </section>
      <section>
        <h3>Security contributors</h3>
        <ul>
          <li>Submit high-quality reports on malicious QR payloads and wallet-drain patterns.</li>
          <li>Help validate suspicious domains, redirects, and crypto transaction prompts.</li>
          <li>Contribute documentation, test cases, and detection ideas.</li>
        </ul>
      </section>
      <section>
        <h3>SafeScan treasury</h3>
        <ul>
          <li>Fund product development, API infrastructure, abuse response, and audits.</li>
          <li>Support integrations with wallets, merchants, browsers, and mobile clients.</li>
          <li>Maintain reserves for responsible ecosystem operations.</li>
        </ul>
      </section>
    </div>

    <h2>Utility design principles</h2>
    <ul>
      <li><strong>Security first:</strong> utility should strengthen user safety rather than encourage risky behavior.</li>
      <li><strong>Transparent rules:</strong> access, rewards, and contributor programs should be documented before launch.</li>
      <li><strong>Regulatory aware:</strong> distribution and access rules should respect applicable law and platform policy.</li>
      <li><strong>Product anchored:</strong> token utility should map to real SafeScan usage, not vague speculation.</li>
      <li><strong>Abuse resistant:</strong> fraud controls should reduce bot activity, duplicate accounts, and low-quality reporting.</li>
    </ul>

    <h2>Risk controls</h2>
    <p>SafeScan should continue to enforce account integrity, scan velocity checks, wallet reuse detection, report review workflows, admin audit logs, and anti-abuse controls. Token-related features should be gated by identity, reputation, and operational review where needed.</p>

    <h2>Roadmap</h2>
    <ol>
      <li><strong>Phase 1:</strong> publish SafeScan risk engine, scan history, profile, wallet verification, and reporting flows.</li>
      <li><strong>Phase 2:</strong> release developer documentation for QR risk scoring, merchant safety checks, and wallet-flow analysis.</li>
      <li><strong>Phase 3:</strong> define $SQR access rules, contributor criteria, API credit mechanics, and ecosystem governance boundaries.</li>
      <li><strong>Phase 4:</strong> complete legal, security, and operational review before any public token launch.</li>
    </ol>

    <h2>Disclaimer</h2>
    <p>$SQR is a proposed utility design for the SafeScan QR ecosystem. Features, launch timing, access rules, and allocation categories may change. Nothing on this page is a promise of token value, profit, availability, or eligibility.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "$SQR Tokenomics", body))

@qr_app.get("/legal/do-not-sell", response_class=HTMLResponse)
async def do_not_sell(request: Request):
    body = """
    <h2>Do Not Sell or Share My Personal Information</h2>
    <p>SafeScan does not sell personal information and does not use advertising networks. California residents can still submit a formal opt-out of sale/sharing or cross-context behavioral advertising.</p>
    <form class="legal-form" action="/legal/data-request" method="post">
      <input type="hidden" name="request_type" value="do_not_sell">
      <input type="hidden" name="region" value="California">
      <label>Email <input type="email" name="email" required placeholder="you@example.com"></label>
      <label>Details <textarea name="details" rows="4">I opt out of sale or sharing of my personal information.</textarea></label>
      <button class="primary-button" type="submit">Submit opt-out</button>
    </form>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Do Not Sell or Share", body))

@qr_app.get("/legal/data-request", response_class=HTMLResponse)
async def data_request_page(request: Request, email: str = Query("")):
    return templates.TemplateResponse("data_request.html", {
        "request": request, "email": email, "message": "", "export_data": "",
        "version": LEGAL_VERSION, "last_updated": LEGAL_LAST_UPDATED
    })

@qr_app.post("/legal/data-request", response_class=HTMLResponse)
async def submit_data_request(
    request: Request,
    email: str = Form(...),
    region: str = Form(""),
    request_type: str = Form(...),
    details: str = Form("")
):
    request_id = make_id("dsr")
    now = datetime.utcnow().isoformat() + "Z"
    export_data = ""
    status = "submitted"
    session_user = get_session_user(request)
    verified_self_request = session_user and session_user.get("email") == email.strip().lower()
    if request_type in ("access", "portability"):
        if verified_self_request:
            export_data = json.dumps(get_user_export(email), indent=2)
            status = "completed"
    elif request_type == "erasure":
        if verified_self_request:
            delete_user_data(email)
            status = "completed"
            audit_log("account.deleted", request=request, actor_user_id=session_user.get("google_id"), target_type="user", target_id=email)
    elif request_type in ("do_not_sell", "limit_sensitive", "object", "revoke_consent"):
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO privacy_opt_outs VALUES (?, ?, ?, ?, ?)",
                (make_id("opt"), email, region, request_type, now)
            )

    with get_conn() as conn:
        conn.execute(
            "INSERT INTO data_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (request_id, email, region, request_type, details, status, now, now if status == "completed" else None)
        )

    message = f"Request {request_id} recorded. Confirmation email hooks are documented; connect an email provider before production."
    return templates.TemplateResponse("data_request.html", {
        "request": request, "email": email, "message": message, "export_data": export_data,
        "version": LEGAL_VERSION, "last_updated": LEGAL_LAST_UPDATED
    })

@qr_app.post("/api/consent")
async def log_consent(request: Request, payload: dict = Body(...)):
    consent_type = payload.get("consentType", "essential_only")
    consent_given = consent_type != "essential_only"
    now = datetime.utcnow()
    consent_id = make_id("consent")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO consent_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                consent_id,
                payload.get("userId"),
                hash_ip(request_ip(request)),
                int(consent_given),
                consent_type,
                payload.get("bannerVersion", "consent-v1"),
                now.isoformat() + "Z",
                request.headers.get("user-agent", ""),
                locale_from_request(request),
                (now + timedelta(days=365)).isoformat() + "Z"
            )
        )
    return {"id": consent_id, "expiresInDays": 365}

@qr_app.get("/legal/consent-log", response_class=HTMLResponse)
async def consent_log(request: Request, secret: str = Query("")):
    admin_user = require_role_user(request, "admin")
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute("SELECT * FROM consent_logs ORDER BY timestamp DESC LIMIT 200")]
    audit_log("admin.view_logs", request=request, actor_user_id=admin_user.get("google_id"), target_type="consent_logs")
    body = "<table class='legal-table'><thead><tr><th>Time</th><th>User</th><th>Type</th><th>IP Hash</th><th>Locale</th></tr></thead><tbody>"
    body += "".join(f"<tr><td>{row['timestamp']}</td><td>{row['user_id'] or ''}</td><td>{row['consent_type']}</td><td>{row['ip_hash'][:16]}...</td><td>{row['locale'] or ''}</td></tr>" for row in rows)
    body += "</tbody></table>"
    return templates.TemplateResponse("admin_table.html", {"request": request, "title": "Consent Log", "body_html": body, "message": ""})

@qr_app.get("/admin/data-processing-log", response_class=HTMLResponse)
async def data_processing_log(request: Request, secret: str = Query("")):
    admin_user = require_role_user(request, "admin")
    categories = [
        ("OAuth profile", "Authentication", "Contractual necessity", "Google, Render", "Until deletion or 2 years inactivity"),
        ("QR payload URLs", "Risk analysis", "Legitimate interest", "Google Safe Browsing, VirusTotal, AI provider", "90 days"),
        ("Wallet address", "Airdrop eligibility", "Contractual necessity", "Solana RPC providers", "Until disconnect or deletion"),
        ("Consent records", "Compliance evidence", "Legal obligation", "Internal only", "5 years"),
        ("IP hash and user agent", "Fraud prevention", "Legitimate interest", "Render", "90 days unless tied to compliance record"),
    ]
    body = "<table class='legal-table'><thead><tr><th>Data</th><th>Purpose</th><th>Legal Basis</th><th>Shared With</th><th>Retention</th></tr></thead><tbody>"
    body += "".join(f"<tr><td>{a}</td><td>{b}</td><td>{c}</td><td>{d}</td><td>{e}</td></tr>" for a, b, c, d, e in categories)
    body += "</tbody></table><p>CCPA/CPRA threshold note: full statutory obligations may apply once SafeScan reaches $25M annual revenue or processes data of 100,000+ California consumers; these rights are implemented voluntarily now for trust and readiness.</p>"
    audit_log("admin.view_logs", request=request, actor_user_id=admin_user.get("google_id"), target_type="data_processing_log")
    return templates.TemplateResponse("admin_table.html", {"request": request, "title": "Data Processing Log", "body_html": body, "message": ""})

@qr_app.get("/admin/report-breach", response_class=HTMLResponse)
async def report_breach_form(request: Request, secret: str = Query("")):
    require_role_user(request, "admin")
    body = """
    <form class="legal-form" action="/admin/report-breach" method="post">
      <label>Breach discovery date <input name="discovery_date" required placeholder="2026-05-05T14:32:00Z"></label>
      <label>Data categories affected <textarea name="data_categories" required rows="3"></textarea></label>
      <label>Estimated users affected <input name="users_affected" required></label>
      <label>Likely consequences <textarea name="likely_consequences" required rows="4"></textarea></label>
      <label>Measures taken <textarea name="measures_taken" required rows="4"></textarea></label>
      <button class="primary-button" type="submit">Generate breach template</button>
    </form>
    """
    return templates.TemplateResponse("admin_table.html", {"request": request, "title": "Report Breach", "body_html": body, "message": ""})

@qr_app.post("/admin/report-breach", response_class=HTMLResponse)
async def report_breach(
    request: Request,
    discovery_date: str = Form(...),
    data_categories: str = Form(...),
    users_affected: str = Form(...),
    likely_consequences: str = Form(...),
    measures_taken: str = Form(...)
):
    admin_user = require_role_user(request, "admin")
    template = f"""GDPR Article 33/34 Breach Notification Draft\nDiscovery date: {discovery_date}\nData categories affected: {data_categories}\nEstimated users affected: {users_affected}\nLikely consequences: {likely_consequences}\nMeasures taken: {measures_taken}\nAdmin contact: {ADMIN_EMAIL}\nReview whether supervisory authority notice is required within 72 hours and whether user notice is required for high-risk impact."""
    report_id = make_id("breach")
    now = datetime.utcnow().isoformat() + "Z"
    with get_conn() as conn:
        conn.execute("INSERT INTO breach_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (report_id, discovery_date, data_categories, users_affected, likely_consequences, measures_taken, now, template))
    audit_log("admin.breach_report_created", request=request, actor_user_id=admin_user.get("google_id"), target_type="breach_report", target_id=report_id)
    body = f"<h2>Breach Report {report_id}</h2><pre class='legal-json'>{template}</pre>"
    return templates.TemplateResponse("admin_table.html", {"request": request, "title": "Breach Template", "body_html": body, "message": "Report logged. Connect email provider for live admin notifications."})

@qr_app.get("/api/health")
async def api_health():
    """Cheap liveness check the mobile pre-warm hits on app boot.

    Without this, every cold-start ping from `services/endpoints/system.py`
    landed a 404 in the Render logs - the app handled it gracefully via
    a fallback POST /api/analyze, but the noise made it hard to spot
    real 404s in the log stream.
    """
    return {"ok": True, "service": "safescan-qr", "time": now_iso()}


@qr_app.get("/search_qr_api")
async def search_qr_api_get():
    """GET on the form endpoint -> bounce to home.

    `/search_qr_api` is the multipart-upload sibling of the homepage scan
    form. Direct browser visits, social-share previews, and stale-form
    refreshes that land here should not see a partial homepage HTML; they
    should be redirected to the canonical `/` URL.
    """
    return RedirectResponse("/", status_code=303)


@qr_app.post("/search_qr_api", response_class=HTMLResponse)
async def scan_qr(
    request: Request,
    user_email: str = Form(""),
    wallet_address: str = Form(""),
    device_fingerprint: str = Form(""),
    file: UploadFile = File(None),
    manual_url: str = Form(None),
    template_variant: str = Form("")
):
    user = get_session_user(request)
    user_email = user["email"] if user else ""
    test_site = template_variant in ("main_site", "test_site")
    test_site_path = template_variant == "test_site"
    verified_wallet = get_verified_wallet(user_email) if user_email else None
    wallet_address = verified_wallet["address"] if verified_wallet else ""
    url_qr = None
    qr_image_for_ml = None

    if manual_url and manual_url.strip():
        url_qr = manual_url.strip()
    elif file and file.filename:
        contents = await file.read()
        if len(contents) > MAX_QR_UPLOAD_BYTES:
            return templates.TemplateResponse("index.html", {
                "request": request, "logged_in": True, "results_visible": True,
                "status": "ERROR", "url_found": "Uploaded image is too large.",
                "source": "Scanner", "score": "0", "threat_class": "N/A",
                "overall_risk": "suspicious",
                "verdict_summary": "SafeScan limits QR image uploads to keep scans fast and memory usage stable.",
                "reputation": {"provider": "Scanner", "status": "ERROR", "matches": [], "detail": "Upload a smaller image."},
                "risk_reasons": [risk_reason("Upload too large", "medium", f"Use an image under {MAX_QR_UPLOAD_BYTES // (1024 * 1024)} MB.")],
                "virus_total": None,
                "domain_age": None,
                "email": user_email, "scan_count": get_scan_count(user_email) if user_email else 0, "google_client_id": CLIENT_ID,
                "test_site": test_site,
                "test_site_path": test_site_path,
                "version": LEGAL_VERSION,
                **index_user_context(user)
            })
        persist_qr_upload(contents, file.filename, file.content_type, user)
        url_qr, qr_image_for_ml = decode_qr_upload(contents, file.filename, file.content_type)

    if not url_qr:
        return templates.TemplateResponse("index.html", {
            "request": request, "logged_in": True, "results_visible": True,
            "status": "ERROR", "url_found": "No QR code or valid URL detected.",
            "source": "Scanner", "score": "0", "threat_class": "N/A",
            "overall_risk": "suspicious",
            "verdict_summary": "SafeScan could not decode a QR payload from this file.",
            "reputation": {"provider": "Scanner", "status": "ERROR", "matches": [], "detail": "No decodable payload was found."},
            "risk_reasons": [risk_reason("No QR payload decoded", "medium", "Upload a clearer image, SVG, or PDF containing a QR code, or paste the destination manually.")],
            "virus_total": None,
            "domain_age": None,
            "email": user_email, "scan_count": get_scan_count(user_email) if user_email else 0, "google_client_id": CLIENT_ID,
            "test_site": test_site,
            "test_site_path": test_site_path,
            "version": LEGAL_VERSION,
            **index_user_context(user)
        })

    payload_type, _, normalized_payload = detect_payload(url_qr)
    if payload_type == "URL":
        try:
            normalized_payload = validate_public_url(normalized_payload)
            pipeline_response = await analyze_full_pipeline(normalized_payload, qr_image_for_ml)
        except SafeScanError as exc:
            pipeline_response = {
                "url": normalized_payload,
                "overallRisk": "high",
                "confidenceScore": 95,
                "verdict": str(exc),
                "signals": [signal("URL Guard", "Blocked", "high", str(exc), False)],
                "scannedAt": now_iso()
            }
        analysis = pipeline_response_to_template_analysis(pipeline_response)
    else:
        embedded_urls = extract_urls(normalized_payload)
        if embedded_urls:
            try:
                analysis = await analyze_embedded_url_payload(url_qr, embedded_urls[0], qr_image_for_ml)
            except SafeScanError:
                analysis = analyze_qr_payload(url_qr)
        else:
            analysis = analyze_qr_payload(url_qr)
    if qr_image_for_ml is not None:
        qr_image_for_ml.close()
    counted = False
    if user_email:
        counted = record_unique_scan(user_email, url_qr, wallet_address, user_id=user.get("google_id") if user else None)
        save_scan_history(user_email, analysis["normalized"], analysis, user_id=user.get("google_id") if user else None)
        run_fraud_checks("scan", user_email, request, {"url": analysis["normalized"], "deviceFingerprint": device_fingerprint})
    audit_log("qr.scanned", request=request, actor_user_id=user.get("google_id") if user else None, target_type="scan", metadata={"counted": counted, "payloadType": payload_type, "guest": not bool(user_email)})

    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": True,
        "status": analysis["status"], "url_found": analysis["normalized"], "source": analysis["source"],
        "score": analysis["score"],
        "threat_class": analysis["threat_class"],
        "action_description": analysis.get("action_description"),
        "overall_risk": analysis.get("overallRisk", analysis["status"].lower()),
        "verdict_summary": analysis.get("verdict", analysis["threat_class"]),
        "reputation": analysis.get("reputation"),
        "risk_reasons": analysis.get("reasons", []),
        "virus_total": analysis.get("virusTotal"),
        "domain_age": analysis.get("domainAge"),
        "ml_risk": analysis.get("mlRisk"),
        "email": user_email, "scan_count": get_scan_count(user_email) if user_email else 0, "google_client_id": CLIENT_ID,
        "test_site": test_site,
        "test_site_path": test_site_path,
        "version": LEGAL_VERSION,
        **index_user_context(user)
    })

@qr_app.post("/auth/google", response_class=HTMLResponse)
@qr_app.get("/auth/google", response_class=HTMLResponse)
async def auth_google(
    request: Request,
    credential: str = Form(None),
    remember_me: str = Form("1"),
    next_url: str = Form("", alias="next"),
    next_query: str = Query("", alias="next"),
    state: str = Form("", alias="state"),
    state_query: str = Query("", alias="state"),
):
    return_to = safe_next_url(request, next_url or next_query or state or state_query)
    if not credential:
        return templates.TemplateResponse("index.html", {
            "request": request, "logged_in": False, "results_visible": False,
            "email": "", "score": "0", "threat_class": "N/A",
            "scan_count": 0, "google_client_id": CLIENT_ID,
            "test_site": True, "test_site_path": False,
            "version": LEGAL_VERSION,
            **index_user_context(None)
        })
    try:
        idinfo = id_token.verify_oauth2_token(credential, google_requests.Request(), CLIENT_ID)
        google_id = idinfo["sub"]
        user_email = idinfo["email"].strip().lower()
    except ValueError:
        audit_log("auth.failed", request=request, metadata={"provider": "google"})
        raise HTTPException(status_code=401, detail="Authentication required.")

    google_id = save_user_to_db(google_id, user_email, request, idinfo.get("name") or "", idinfo.get("picture") or "")
    user = require_user_from_google_id(google_id)
    if user["status"] != "active":
        raise HTTPException(status_code=401, detail="Authentication required.")
    run_fraud_checks("signup", user_email, request, {"googleId": google_id})
    session_id = create_session(google_id, request)
    audit_log("user.login", request=request, actor_user_id=google_id)
    if return_to != "/":
        response = RedirectResponse(return_to, status_code=303)
        set_session_cookie(response, session_id)
        if wants_remember_me(remember_me):
            issue_remember_me_cookie(response, google_id, request)
        return response
    response = templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": False,
        "email": user_email, "score": "0", "threat_class": "N/A",
        "scan_count": get_scan_count(user_email), "google_client_id": CLIENT_ID,
        "test_site": True, "test_site_path": False,
        "version": LEGAL_VERSION,
        **index_user_context(user)
    })
    set_session_cookie(response, session_id)
    if wants_remember_me(remember_me):
        issue_remember_me_cookie(response, google_id, request)
    return response

@qr_app.post("/auth/verify")
async def auth_verify(request: Request, payload: dict = Body(...)):
    # Per-IP throttle BEFORE any token validation work. Without this, an
    # attacker can hammer the JWKS verifier with garbage tokens and burn
    # CPU + Auth0 JWKS fetches. 20 attempts per 15 min from a single IP is
    # generous for real users (re-login retries, etc.) but kills brute force.
    ip_rate_limit = enforce_rate_limit(request, "auth_verify_ip", 20, 15 * 60)
    if ip_rate_limit:
        return ip_rate_limit

    validate_strict_payload(payload, {"token"})
    credential = (payload.get("token") or "").strip()
    if not credential:
        raise HTTPException(status_code=400, detail="Invalid request.")

    # Mobile clients can present either a Google-signed idToken or an
    # Auth0-signed idToken (when signing in via Auth0 Universal Login). Pick
    # the verifier based on the JWT issuer.
    provider = "google_mobile"
    try:
        _, unverified_payload, _ = _decode_jwt_unverified(credential)
        issuer = (unverified_payload.get("iss") or "").rstrip("/")
    except (ValueError, KeyError, TypeError):
        issuer = ""

    try:
        if issuer == AUTH0_ISSUER.rstrip("/"):
            provider = "auth0_mobile"
            idinfo = verify_auth0_id_token(credential)
            # Auth0 user_id format for Google connection: "google-oauth2|<sub>".
            raw_sub = idinfo.get("sub") or ""
            if "|" in raw_sub:
                google_id = raw_sub.split("|", 1)[1]
            else:
                google_id = raw_sub
            if not google_id:
                raise ValueError("Auth0 token missing subject.")
            user_email = (idinfo.get("email") or "").strip().lower()
            if not user_email:
                raise ValueError("Auth0 token missing email.")
        else:
            idinfo = id_token.verify_oauth2_token(credential, google_requests.Request(), CLIENT_ID)
            google_id = idinfo["sub"]
            user_email = idinfo["email"].strip().lower()
    except ValueError:
        audit_log("auth.failed", request=request, metadata={"provider": provider})
        raise HTTPException(status_code=401, detail="Authentication required.")

    google_id = save_user_to_db(google_id, user_email, request, idinfo.get("name") or "", idinfo.get("picture") or "")
    user = require_user_from_google_id(google_id)
    if user["status"] != "active":
        raise HTTPException(status_code=401, detail="Authentication required.")
    run_fraud_checks("signup", user_email, request, {"googleId": google_id, "client": "mobile", "provider": provider})
    session_id = create_session(google_id, request)
    audit_log("user.login", request=request, actor_user_id=google_id, metadata={"client": "mobile", "provider": provider})
    return {
        "session": session_id,
        "user": {
            "id": google_id,
            "name": user.get("display_name") or idinfo.get("name") or "Safe scanner",
            "email": user_email,
            "avatarUrl": idinfo.get("picture"),
            "role": user.get("role", "user"),
        },
    }

async def _do_logout(request: Request):
    session_id = request_session_id(request)
    user = get_session_user(request)
    if session_id:
        with get_conn() as conn:
            conn.execute("UPDATE sessions SET revoked_at = ? WHERE id = ?", (now_iso(), session_id))
    if user:
        revoke_all_remember_me(user.get("google_id"))
    audit_log("user.logout", request=request, actor_user_id=user.get("google_id") if user else None)
    response = RedirectResponse("/", status_code=303)
    clear_session_cookie(response)
    clear_remember_me_cookie(response)
    return response

@qr_app.post("/auth/logout")
async def logout_post(request: Request):
    return await _do_logout(request)

@qr_app.get("/auth/logout")
async def logout_get(request: Request):
    return await _do_logout(request)

@qr_app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = Query(""), tab: str = Query("login"), next_url: str = Query("/", alias="next")):
    user = get_session_user(request)
    return_to = safe_next_url(request, next_url)
    if user:
        return RedirectResponse(return_to, status_code=303)
    auth_google_url = f"{APP_URL}/auth/google"
    return templates.TemplateResponse("login.html", {"request": request, "error": error, "tab": tab, "next_url": return_to, "local_auth_enabled": LOCAL_AUTH_ENABLED, "google_client_id": CLIENT_ID or "", "auth_google_url": auth_google_url})

@qr_app.post("/auth/register", response_class=HTMLResponse)
async def auth_register(request: Request, email: str = Form(...), password: str = Form(...), remember_me: str = Form("1"), next_url: str = Form("/", alias="next")):
    rate_limited = enforce_rate_limit(request, "register", 5, 3600)
    if rate_limited:
        return rate_limited
    if get_session_user(request):
        return duplicate_account_response(request, "You are already signed in. Sign out before creating a new account.")
    email = email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email address.", "tab": "register"})
    if len(password) < 8:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Password must be at least 8 characters.", "tab": "register"})
    if email_account_exists(email):
        return duplicate_account_response(request)
    lid = save_local_user(email, request)
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO local_credentials (email, password_hash, created_at, user_id) VALUES (?, ?, ?, ?)",
                (email, hash_password(password), now_iso(), lid)
            )
    except sqlite3.IntegrityError:
        return duplicate_account_response(request)
    run_fraud_checks("signup", email, request, {})
    session_id = create_session(lid, request)
    audit_log("user.register", request=request, actor_user_id=lid)
    response = response_after_login(lid, request, next_url)
    set_session_cookie(response, session_id)
    if wants_remember_me(remember_me):
        issue_remember_me_cookie(response, lid, request)
    return response

@qr_app.post("/auth/login", response_class=HTMLResponse)
async def auth_login_local(request: Request, email: str = Form(...), password: str = Form(...), remember_me: str = Form("1"), next_url: str = Form("/", alias="next")):
    rate_limited = enforce_rate_limit(request, "login_local", 10, 600)
    if rate_limited:
        return rate_limited
    email = email.strip().lower()
    with get_conn() as conn:
        row = conn.execute("SELECT password_hash, user_id FROM local_credentials WHERE email = ?", (email,)).fetchone()
    if not row or not verify_password(password, row[0]):
        audit_log("auth.failed", request=request, metadata={"provider": "local"})
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid email or password.", "tab": "login"})
    lid = save_local_user(email, request)
    with get_conn() as conn:
        conn.execute("UPDATE local_credentials SET user_id = ? WHERE email = ?", (lid, email))
    user = require_user_from_google_id(lid)
    if user["status"] != "active":
        raise HTTPException(status_code=401, detail="Authentication required.")
    session_id = create_session(lid, request)
    audit_log("user.login", request=request, actor_user_id=lid, metadata={"provider": "local"})
    response = response_after_login(lid, request, next_url)
    set_session_cookie(response, session_id)
    if wants_remember_me(remember_me):
        issue_remember_me_cookie(response, lid, request)
    return response

@qr_app.post("/auth/dev-google")
async def auth_dev_google(request: Request, remember_me: str = Form("1"), next_url: str = Form("/", alias="next")):
    if not LOCAL_AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Not found.")
    google_id = "dev-google-local"
    user_email = "google-demo@safescan.local"
    google_id = save_user_to_db(google_id, user_email, request)
    user = require_user_from_google_id(google_id)
    if user["status"] != "active":
        raise HTTPException(status_code=401, detail="Authentication required.")
    run_fraud_checks("signup", user_email, request, {"googleId": google_id, "client": "local"})
    session_id = create_session(google_id, request)
    audit_log("user.login", request=request, actor_user_id=google_id, metadata={"provider": "google_local"})
    response = response_after_login(google_id, request, next_url)
    set_session_cookie(response, session_id)
    if wants_remember_me(remember_me):
        issue_remember_me_cookie(response, google_id, request)
    return response

@qr_app.get("/onboarding/username", response_class=HTMLResponse)
async def username_onboarding_page(request: Request, error: str = Query("")):
    return RedirectResponse(f"/profile?error={quote(error)}" if error else "/profile", status_code=303)

@qr_app.post("/onboarding/username", response_class=HTMLResponse)
async def username_onboarding_submit(request: Request, username: str = Form(...)):
    return await profile_username_submit(request, username)

@qr_app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, error: str = Query("")):
    user = require_user(request)
    email = user["email"]
    username = (user.get("username") or "").strip()
    return templates.TemplateResponse("profile.html", {
        "request": request,
        **index_user_context(user),
        "email": email,
        "username": username,
        "scan_count": get_scan_count(email),
        "leaderboard_status": "Live" if username else "Hidden",
        "error": error,
    })

@qr_app.post("/profile/username", response_class=HTMLResponse)
async def profile_username_submit(request: Request, username: str = Form(...)):
    user = require_user(request)
    try:
        set_user_username(user["google_id"], username)
    except SafeScanError as exc:
        return templates.TemplateResponse("profile.html", {
            "request": request,
            **index_user_context(user),
            "email": user.get("email"),
            "username": (user.get("username") or "").strip(),
            "scan_count": get_scan_count(user.get("email")),
            "leaderboard_status": "Live" if (user.get("username") or "").strip() else "Hidden",
            "error": str(exc),
        }, status_code=400)
    audit_log("user.username_set", request=request, actor_user_id=user["google_id"])
    destination = "/" if request.url.path == "/onboarding/username" else "/profile"
    return RedirectResponse(destination, status_code=303)

@qr_app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    user = get_session_user(request)
    email = user["email"] if user else ""
    scans = []
    if user:
        with get_conn() as conn:
            rows = user_scoped_select(conn, "scan_history")
            rows = sorted(rows, key=lambda row: row["created_at"] or "", reverse=True)[:100]
            scans = [dict(r) for r in rows]
    return templates.TemplateResponse("history.html", {"request": request, "email": email, "scans": scans})

@qr_app.get("/leaderboard", response_class=HTMLResponse)
async def leaderboard_page(request: Request):
    user = get_session_user(request)
    email = user["email"] if user else ""
    return templates.TemplateResponse("leaderboard.html", {
        "request": request,
        "email": email,
        "username": user.get("username") if user else "",
        "current_user_id": user.get("google_id") if user else "",
        "leaders": get_global_leaderboard(50),
        "started_at": APP_STARTED_AT.isoformat() + "Z",
    })

@qr_app.get("/auth/confirm-age", response_class=HTMLResponse)
async def confirm_age_page(request: Request, email: str = Query(...), locale: str = Query("en-US"), threshold: int = Query(13)):
    threshold = 16 if is_eu_locale(locale) else threshold
    return templates.TemplateResponse("confirm_age.html", {
        "request": request, "email": email, "locale": locale, "threshold": threshold, "blocked": False
    })

@qr_app.post("/auth/confirm-age", response_class=HTMLResponse)
async def confirm_age_submit(
    request: Request,
    email: str = Form(...),
    locale: str = Form("en-US"),
    threshold: int = Form(13),
    confirmed: str = Form("no")
):
    threshold = 16 if is_eu_locale(locale) else threshold
    if confirmed != "yes":
        return templates.TemplateResponse("confirm_age.html", {
            "request": request, "email": email, "locale": locale, "threshold": threshold, "blocked": True
        })
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO age_confirmations VALUES (?, ?, ?, ?)",
            (email, threshold, locale, datetime.utcnow().isoformat() + "Z")
        )
    return templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": False,
        "email": email, "score": "0", "threat_class": "N/A",
        "scan_count": get_scan_count(email), "google_client_id": CLIENT_ID,
        "test_site": True, "test_site_path": False,
        "version": LEGAL_VERSION,
        **index_user_context(get_session_user(request))
    })

@qr_app.get("/account/settings", response_class=HTMLResponse)
async def account_settings(request: Request, email: str = Query("")):
    user = require_user(request)
    email = user["email"]
    body = f"""
    <h2>Account Settings</h2>
    <p>Use this page to revoke non-essential consent with one click. This supports LGPD and general privacy readiness.</p>
    <form class="legal-form" action="/legal/data-request" method="post">
      <input type="hidden" name="request_type" value="revoke_consent">
      <input type="hidden" name="region" value="">
      <input type="hidden" name="details" value="One-click consent revocation from account settings.">
      <label>Email <input type="email" name="email" required value="{email}" placeholder="you@example.com"></label>
      <button class="danger-button" type="submit">Revoke Consent</button>
    </form>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Account Settings", body))

@qr_app.get("/trigger-airdrop-secret")
async def trigger_airdrop(
    request: Request,
    secret: str = Query(None),
    x_airdrop_secret: str = Header(None)
):
    admin_user = get_session_user(request)
    provided_secret = x_airdrop_secret or secret
    if admin_user:
        require_role_user(request, "admin")
    elif not (AIRDROP_ADMIN_SECRET and provided_secret == AIRDROP_ADMIN_SECRET):
        audit_log("auth.permission_denied", request=request, target_type="airdrop")
        raise HTTPException(status_code=403, detail="You do not have permission to do this.")

    try:
        from distribute import airdrop_sweep
        result = await airdrop_sweep()
        audit_log(
            "airdrop.sweep_executed",
            request=request,
            actor_user_id=admin_user.get("google_id") if admin_user else None,
            target_type="airdrop",
            metadata={
                "qualified": result.get("eligible", 0),
                "sent": len(result.get("sent", [])),
                "totalTokens": result.get("total_tokens_sent", 0),
                "status": result.get("status")
            }
        )
        return {
            "status": result.get("status", "ok"),
            "message": "Airdrop sweep executed.",
            "result": result
        }
    except Exception as e:
        audit_log("airdrop.sweep_failed", request=request, actor_user_id=admin_user.get("google_id") if admin_user else None, target_type="airdrop", metadata={"error": type(e).__name__})
        return {
            "status": "Failed",
            "error": "Airdrop sweep failed.",
            "error_type": type(e).__name__
        }

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



# print("Testing URL bad:")
# print(check_url("http://testsafebrowsing.appspot.com/s/malware.html"))

# print("Testing URL good:")
# print(check_url("https://google.com"))
