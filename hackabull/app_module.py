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
from .auth import create_session
from .auth import get_session_user
from .config import ACTIVE_SCANS
from .config import ALLOWED_ORIGINS
from .config import CONTENT_TYPE_LATEST
from .config import REMEMBER_ME_COOKIE_NAME
from .config import REQUEST_COUNT
from .config import REQUEST_LATENCY
from .config import SESSION_COOKIE_NAME
from .config import generate_latest
from .request_helpers import request_ip
from .security import enforce_rate_limit
from .sessions import cleanup_persistent_sessions
from .sessions import clear_remember_me_cookie
from .sessions import set_remember_me_cookie
from .sessions import set_session_cookie
from .sessions import validate_and_rotate_remember_me
from .wallet import cleanup_wallet_nonces
from .wallet import expire_alpha_subscriptions

# =============================================================================
# FASTAPI APP, MIDDLEWARE & ERROR HANDLERS
# Below: the app object, health/metrics endpoints, the middleware stack
# (origin checks, RLS context, remember-me, security headers, rate limits) and
# centralised exception handlers. The route handlers follow.
# =============================================================================
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

    if getattr(request.state, "remembered_user", None):
        response = await call_next(request)
        session_id = getattr(request.state, "remembered_session_id", None)
        rotated_token = getattr(request.state, "rotated_remember_token", None)
        if session_id:
            set_session_cookie(response, session_id)
        if rotated_token:
            set_remember_me_cookie(response, rotated_token)
        return response

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
    "img-src 'self' data: blob: https://lh3.googleusercontent.com https://ssl.gstatic.com https://www.gstatic.com",
    # VirusTotal, Google Safe Browsing, Solana RPC, and the AI verdict
    # providers (Anthropic/OpenAI) are all called server-side via `requests`
    # - the browser never connects to them directly, so they're deliberately
    # left out of connect-src to keep the XSS exfiltration surface minimal.
    "connect-src 'self' https://safescan-qr.onrender.com https://accounts.google.com https://cdn.jsdelivr.net",
    "frame-src https://accounts.google.com https://www.youtube.com https://www.youtube-nocookie.com",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "base-uri 'self'",
    "upgrade-insecure-requests",
])

PERMISSIONS_POLICY = ", ".join([
    "camera=(self)",
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
    # Loudly flag non-persistent storage at boot. The leaderboard, sessions and
    # scan history all live in SQLite; if the DB isn't on a persistent disk it
    # is rebuilt on every deploy/restart and the board appears to "randomly
    # wipe". This makes a misconfigured deploy obvious in the logs.
    storage_status = database_storage_status()
    if not storage_status.get("persistent"):
        print({
            "warning": "non_persistent_database",
            "message": storage_status.get("warning"),
            "path": storage_status.get("path"),
            "hint": "Mount a Render disk at /var/data (or set DATA_DIR to a durable path) so the leaderboard and scan history survive deploys.",
        })
    cleanup_persistent_sessions()
    expire_alpha_subscriptions()
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

