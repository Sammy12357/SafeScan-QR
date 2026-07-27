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

# =============================================================================
# OPTIONAL PROMETHEUS METRICS
# If prometheus_client isn't installed we fall back to no-op stand-ins so the
# rest of the app can call .inc()/.observe() unconditionally.
# =============================================================================
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

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration

CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID") or os.getenv("googe_client_id")
# Auth0 mobile sign-in configuration. Production must set both variables in
# Render; see .env.example and DEPLOYMENT.md. The fallback values exist only so
# older local-development setups keep starting. A tenant mismatch causes
# /auth/verify to reject the token because its issuer will not match.
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
WHOISXML_API_KEY = os.getenv("WHOISXML_API_KEY")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY")
DOMAIN_AGE_CACHE_TTL_DAYS = int(os.getenv("DOMAIN_AGE_CACHE_TTL_DAYS", "30"))
DOMAIN_AGE_CHECK_ENABLED = os.getenv("DOMAIN_AGE_CHECK_ENABLED", "true").lower() in ("1", "true", "yes", "on")
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
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
ALPHA_SOLANA_RECIPIENT = os.getenv("ALPHA_SOLANA_RECIPIENT", "").strip()
ALPHA_SOLANA_AMOUNT_SOL = os.getenv("ALPHA_SOLANA_AMOUNT_SOL", "").strip()
ALPHA_SOLANA_PRICE_USD = Decimal(os.getenv("ALPHA_SOLANA_PRICE_USD", "1.00"))
ALPHA_SOLANA_QUOTE_TTL_SECONDS = int(os.getenv("ALPHA_SOLANA_QUOTE_TTL_SECONDS", "600"))
SOLANA_USD_PRICE_FALLBACK = os.getenv("SOLANA_USD_PRICE_FALLBACK", "").strip()
SOLANA_USD_PRICE_URL = os.getenv("SOLANA_USD_PRICE_URL", "https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd").strip()
ALPHA_SOLANA_ACCESS_DAYS = int(os.getenv("ALPHA_SOLANA_ACCESS_DAYS", "30"))
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
# Default bumped 0.50 -> 0.70 and cap raised 0.70 -> 0.85 (2026-06-04): when
# the ML model fires a high-confidence signal it now drives 70% of the blend
# by default, so a strong malicious prediction can pull a borderline rule
# score into the danger band. The non_ml_high "high-rule floor" at line 1881
# still prevents ML from dragging a confirmed-bad URL into safe territory.
ML_AGGREGATE_WEIGHT = max(0.0, min(0.85, float(os.getenv("SAFESCAN_ML_WEIGHT", "0.70"))))
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
# Single-label TLDs that show up disproportionately in spam/phishing/scam
# campaigns because they're cheap (often <$2/yr) and effectively unmoderated.
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf",
    ".sbs", ".icu", ".cc", ".cyou", ".cfd", ".rest", ".buzz",
    ".mom", ".lol", ".work", ".fit", ".bid", ".loan", ".win",
    ".live", ".support", ".monster", ".cam",
}

# Two-label suffixes (ccTLD second-level domains) that are similarly cheap
# / loosely moderated and frequently abused for disposable phishing pages
# despite belonging to a "real" country code.
HIGH_RISK_TWO_LABEL_TLDS = {".com.py", ".com.cm", ".com.de"}

URL_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}

# Well-known brands frequently impersonated by typosquatted domains, mapped
# to their real registrable domain. A scanned domain whose registrable label
# is a near-miss (small edit distance) of one of these keys - but isn't the
# real domain - is almost always a phishing/credential-harvesting page.
PROTECTED_BRANDS = {
    "roblox": "roblox.com",
    "steamcommunity": "steamcommunity.com",
    "steampowered": "steampowered.com",
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "metamask": "metamask.io",
    "discord": "discord.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com",
    "ebay": "ebay.com",
    "linkedin": "linkedin.com",
    "twitter": "twitter.com",
    "x": "x.com",
}
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MALICIOUS_CONTRACT_BLOCKLIST = {
    "11111111111111111111111111111111",
    "drainwallet111111111111111111111111111111",
}

templates = Jinja2Templates(directory="templates")
_template_response = templates.TemplateResponse


# =============================================================================
# SMALL FORMATTING & TEMPLATE HELPERS
# =============================================================================
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

