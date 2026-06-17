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
from .app_module import qr_app
from .audit import audit_log
from .audit import now_iso
from .auth import get_session_user
from .auth import require_role_user
from .auth import require_user
from .config import AIRDROP_ADMIN_SECRET
from .config import APP_STARTED_AT
from .config import CLIENT_ID
from .config import LEGAL_VERSION
from .config import templates
from .history import group_scan_history
from .history import index_user_context
from .history import serialize_scan_history_row
from .leaderboard import MALICIOUS_RISK_THRESHOLD
from .leaderboard import get_global_leaderboard
from .legal import legal_context
from .malicious_db import get_malicious_qr_codes
from .malicious_db import render_threat_qr_png
from .referrals import get_scan_count
from .request_helpers import is_eu_locale
from .security import enforce_rate_limit

@qr_app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    user = get_session_user(request)
    email = user["email"] if user else ""
    scans = []
    scan_groups = []
    if user:
        with get_conn() as conn:
            rows = user_scoped_select(conn, "scan_history")
            rows = sorted(rows, key=lambda row: row["created_at"] or "", reverse=True)[:100]
            scans = [serialize_scan_history_row(row) for row in rows]
            scan_groups = group_scan_history(scans)
    return templates.TemplateResponse("history.html", {"request": request, "email": email, "scans": scans, "scan_groups": scan_groups})

@qr_app.get("/api/leaderboard")
async def api_leaderboard(request: Request, limit: int = Query(50)):
    """Live global leaderboard as JSON for the mobile app.

    Aggregates every recorded scan across the scans / scan_history /
    scan_events tables (same source as the website leaderboard page) and
    returns the top N users by scan count. Session is optional - when
    present we flag the current user so the app can highlight their row.
    """
    user = get_session_user(request)
    current_id = user.get("google_id") if user else None
    current_email = (user.get("email") or "").strip().lower() if user else None
    leaders = get_global_leaderboard(limit)
    entries = []
    for row in leaders:
        row_email = (row.get("email") or "").strip().lower()
        is_current = bool(
            (current_id and row.get("user_id") == current_id)
            or (current_email and row_email and row_email == current_email)
        )
        entries.append({
            "rank": row.get("rank"),
            "name": row.get("public_name") or "SafeScan user",
            "scans": int(row.get("scan_count") or 0),
            "totalSaved": int(row.get("total_saved_scans") or 0),
            "lastScannedAt": row.get("last_scanned_at"),
            "isCurrentUser": is_current,
        })
    return {
        "entries": entries,
        "total": len(entries),
        "updatedAt": now_iso(),
    }

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

@qr_app.get("/api/malicious-qr")
async def api_malicious_qr(request: Request, page: int = Query(1), limit: int = Query(20), q: str = Query("")):
    """Public JSON feed of QR payloads flagged malicious, paginated and
    optionally filtered by URL substring. No authentication required."""
    rate_limit = enforce_rate_limit(request, "malicious_qr_list", 120, 60)
    if rate_limit:
        return rate_limit
    return get_malicious_qr_codes(page=page, limit=limit, query=q)

@qr_app.get("/api/qr-codes")
async def api_qr_codes(
    request: Request,
    malicious: bool = Query(False),
    page: int = Query(1),
    limit: int = Query(20),
    q: str = Query(""),
):
    """Compatibility QR-code listing endpoint.

    The public threat database uses /api/malicious-qr directly, while this
    endpoint keeps the requested /api/qr-codes?malicious=true shape available
    for clients that expect a generic QR-code collection route.
    """
    if not malicious:
        raise HTTPException(status_code=400, detail="Only malicious=true is supported for public QR listings.")
    rate_limit = enforce_rate_limit(request, "malicious_qr_list", 120, 60)
    if rate_limit:
        return rate_limit
    return get_malicious_qr_codes(page=page, limit=limit, query=q)

@qr_app.get("/api/malicious-qr/image")
async def api_malicious_qr_image(request: Request, u: str = Query(...)):
    """Regenerated QR graphic for a known-malicious URL. Only renders codes
    that actually exist in the database as malicious, so this can't be used as
    a generic QR generator for arbitrary (or safe) URLs."""
    rate_limit = enforce_rate_limit(request, "malicious_qr_image", 120, 60)
    if rate_limit:
        return rate_limit
    target = (u or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Missing URL.")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM scan_history WHERE url = ? AND "
            "(COALESCE(risk_score, 0) >= ? OR upper(COALESCE(verdict, '')) = 'MALICIOUS') LIMIT 1",
            (target, MALICIOUS_RISK_THRESHOLD),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Not a known malicious QR.")
    png = render_threat_qr_png(target)
    return Response(
        content=png,
        media_type="image/png",
        headers={"Cache-Control": "public, max-age=86400"},
    )

@qr_app.get("/malicious-database", response_class=HTMLResponse)
async def malicious_database_page(request: Request):
    """Public "codes to avoid" board listing every scanned malicious QR.

    The list itself is fetched client-side from /api/malicious-qr so search and
    pagination work without page reloads; the template only needs the page size.
    """
    return templates.TemplateResponse("malicious_database.html", {
        "request": request,
        "limit": 20,
    })

@qr_app.get("/generate-qr", response_class=HTMLResponse)
async def generate_qr_page(request: Request):
    """Standalone SafeScan QR generator tab."""
    user = get_session_user(request)
    return templates.TemplateResponse("generate_qr.html", {
        "request": request,
        "logged_in": bool(user),
        "email": user["email"] if user else "",
        "test_site_path": False,
        "active_nav": "generate",
        "google_client_id": CLIENT_ID,
        **index_user_context(user),
    })

@qr_app.get("/plans", response_class=HTMLResponse)
async def plans_page(request: Request):
    """Standalone plans/pricing tab."""
    user = get_session_user(request)
    return templates.TemplateResponse("plans.html", {
        "request": request,
        "logged_in": bool(user),
        "email": user["email"] if user else "",
        "test_site_path": False,
        "active_nav": "plans",
        "google_client_id": CLIENT_ID,
        **index_user_context(user),
    })

@qr_app.get("/learn", response_class=HTMLResponse)
async def learn_page(request: Request):
    """Educational hub: quishing explainer, pre-scan checklist, and wallet-drain pattern guide."""
    user = get_session_user(request)
    return templates.TemplateResponse("learn.html", {
        "request": request,
        "logged_in": bool(user),
        "email": user["email"] if user else "",
        "test_site_path": False,
        "active_nav": "learn",
        "google_client_id": CLIENT_ID,
        **index_user_context(user),
    })

@qr_app.get("/token", response_class=HTMLResponse)
async def token_page(request: Request):
    """Standalone SQR token & airdrop tab."""
    user = get_session_user(request)
    email = user["email"] if user else ""
    return templates.TemplateResponse("token.html", {
        "request": request,
        "logged_in": bool(user),
        "email": email,
        "scan_count": get_scan_count(email) if email else 0,
        "test_site_path": False,
        "active_nav": "token",
        "google_client_id": CLIENT_ID,
        **index_user_context(user),
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




# print("Testing URL bad:")
# print(check_url("http://testsafebrowsing.appspot.com/s/malware.html"))

# print("Testing URL good:")
# print(check_url("https://google.com"))


