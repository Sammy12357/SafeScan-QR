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
from urllib.parse import parse_qs
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
from .age_gate import ACCOUNT_MIN_AGE
from .age_gate import ADULT_MIN_AGE
from .age_gate import ADULT_CHALLENGE_COOKIE
from .age_gate import GUEST_ADULT_COOKIE
from .age_gate import GUEST_ADULT_SECONDS
from .age_gate import PENDING_COOKIE
from .age_gate import PENDING_SECONDS
from .age_gate import account_is_adult
from .age_gate import age_from_year
from .age_gate import consume_adult_challenge
from .age_gate import consume_sign_in
from .age_gate import create_adult_challenge
from .age_gate import create_guest_adult_ticket
from .age_gate import guest_is_adult
from .age_gate import pending_sign_in
from .age_gate import record_adult_attestation
from .accounts import response_after_login
from .accounts import safe_next_url
from .audit import audit_log
from .audit import now_iso
from .auth import get_session_user
from .auth import require_role_user
from .auth import require_user
from .config import APP_URL
from .config import APP_STARTED_AT
from .config import CLIENT_ID
from .config import LEGAL_VERSION
from .config import templates
from .errors import error_response
from .history import group_scan_history
from .history import index_user_context
from .history import serialize_scan_history_row
from .homograph import host_forms
from .leaderboard import get_global_leaderboard
from .legal import legal_context
from .listing_review import listing_rows
from .malicious_db import get_malicious_qr_codes
from .referrals import get_scan_count
from .routes_scan_auth import finish_verified_sign_in
from .routes_scan_auth import mobile_sign_in_body
from .sessions import issue_remember_me_cookie
from .sessions import set_session_cookie
from .request_helpers import is_eu_locale
from .request_helpers import make_id
from .security import enforce_rate_limit
from .token_flags import token_features_enabled
from .email_util import send_email, email_sending_configured
from .config import ADMIN_EMAILS

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
            for scan in scans:
                scan["hostForms"] = host_forms(scan["url"])
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
    """Public, admin-confirmed domain indicators; no personal scan URLs."""
    rate_limit = enforce_rate_limit(request, "malicious_qr_list", 120, 60)
    if rate_limit:
        return rate_limit
    return JSONResponse(
        get_malicious_qr_codes(page=page, limit=limit, query=q),
        headers={"Cache-Control": "no-store"},
    )

@qr_app.get("/api/qr-codes")
async def api_qr_codes(
    request: Request,
    malicious: bool = Query(False),
    page: int = Query(1),
    limit: int = Query(20),
    q: str = Query(""),
):
    """Compatibility endpoint for the sanitized public threat indicators."""
    if not malicious:
        raise HTTPException(status_code=400, detail="Only malicious=true is supported for public QR listings.")
    rate_limit = enforce_rate_limit(request, "malicious_qr_list", 120, 60)
    if rate_limit:
        return rate_limit
    return JSONResponse(
        get_malicious_qr_codes(page=page, limit=limit, query=q),
        headers={"Cache-Control": "no-store"},
    )

@qr_app.get("/api/malicious-qr/image", include_in_schema=False)
async def api_malicious_qr_image(request: Request):
    """Retired: exact QR images could reveal private URL tokens."""
    detail = "Public threat QR images are no longer available."
    return error_response(request, 410, message=detail, extra={"detail": detail})

@qr_app.get("/malicious-database", response_class=HTMLResponse)
async def malicious_database_page(request: Request):
    """Public board of reviewed QR URL observations.

    The list itself is fetched client-side from /api/malicious-qr so search and
    pagination work without page reloads; the template only needs the page size.
    """
    return templates.TemplateResponse("malicious_database.html", {
        "request": request,
        "limit": 20,
    })


@qr_app.get("/malicious-database/policy", response_class=HTMLResponse)
async def listing_policy_page(request: Request):
    return templates.TemplateResponse("listing_policy.html", {"request": request})


@qr_app.get("/malicious-database/dispute/{listing_id}", response_class=HTMLResponse)
async def listing_dispute_form(request: Request, listing_id: str):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        domain, rows = listing_rows(conn, listing_id)
    if not rows:
        raise HTTPException(status_code=404, detail="Listing unavailable.")
    response = templates.TemplateResponse("listing_dispute.html", {
        "request": request, "listing_id": listing_id, "domain": domain,
        "submitted": request.query_params.get("submitted") == "1", "error": "",
        "claim": "", "contact_email": "",
    })
    response.headers["Cache-Control"] = "no-store"
    return response


_DISPUTE_EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z")


@qr_app.post("/malicious-database/dispute/{listing_id}", response_class=HTMLResponse)
async def submit_listing_dispute(request: Request, listing_id: str):
    rate_limit = enforce_rate_limit(request, "listing_dispute", 3, 60 * 60)
    if rate_limit:
        return rate_limit
    if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/x-www-form-urlencoded":
        raise HTTPException(status_code=415, detail="Use the listing dispute form.")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 8192:
            raise HTTPException(status_code=413, detail="Dispute form is too large.")
    try:
        values = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=4)
    except (UnicodeDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid dispute form.")
    if any(len(items) != 1 for items in values.values()) or set(values) - {"contact_email", "claim", "website"}:
        raise HTTPException(status_code=400, detail="Invalid dispute form.")
    email = (values.get("contact_email") or [""])[0].strip().lower()
    claim = (values.get("claim") or [""])[0].strip()
    website = (values.get("website") or [""])[0].strip()
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        domain, rows = listing_rows(conn, listing_id)
        if not rows:
            raise HTTPException(status_code=404, detail="Listing unavailable.")
        if website:
            return RedirectResponse(f"/malicious-database/dispute/{listing_id}?submitted=1", status_code=303)
        error = ""
        if len(email) > 254 or not _DISPUTE_EMAIL.fullmatch(email) or any(len(part) > 63 for part in email.rsplit("@", 1)[1].split(".")):
            error = "Enter a valid contact email address."
        elif not 20 <= len(claim) <= 2000 or any(ord(char) < 32 and char not in "\r\n\t" for char in claim):
            error = "Explain the listing error in 20 to 2,000 characters."
        if error:
            response = templates.TemplateResponse("listing_dispute.html", {
                "request": request, "listing_id": listing_id, "domain": domain,
                "submitted": False, "error": error, "claim": claim[:2000],
                "contact_email": email[:254],
            }, status_code=400)
            response.headers["Cache-Control"] = "no-store"
            return response
        recent = conn.execute(
            "SELECT COUNT(*) FROM listing_disputes WHERE domain = ? AND created_at >= ?",
            (domain, (datetime.utcnow() - timedelta(days=1)).isoformat() + "Z"),
        ).fetchone()[0]
        if recent >= 10:
            raise HTTPException(status_code=429, detail="Too many disputes for this listing today.")
        dispute_id = make_id("dispute")
        conn.execute(
            """INSERT INTO listing_disputes
               (id, domain, contact_email, claim, status, created_at)
               VALUES (?, ?, ?, ?, 'under_review', ?)""",
            (dispute_id, domain, email, claim, now_iso()),
        )
    audit_log("listing.disputed", request=request, target_type="listing_dispute", target_id=dispute_id)
    # Email is transactional. The administrator queue remains authoritative if
    # SMTP is not configured; never include the private claim or contact data.
    if email_sending_configured():
        for admin_email in sorted(ADMIN_EMAILS)[:5]:
            await asyncio.to_thread(
                send_email, admin_email, "SafeScan listing dispute needs review",
                f"<p>A dispute for {domain} needs review.</p><p><a href=\"{APP_URL}/admin/reports?tab=disputes\">Open the admin dispute queue</a>.</p>",
                f"A dispute for {domain} needs review. Open {APP_URL}/admin/reports?tab=disputes",
            )
    return RedirectResponse(f"/malicious-database/dispute/{listing_id}?submitted=1", status_code=303)

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
    if not token_features_enabled():
        response = templates.TemplateResponse("token_unavailable.html", {
            "request": request,
            "logged_in": bool(user),
            "email": email,
            "active_nav": "token",
            **index_user_context(user),
        })
        response.headers["Cache-Control"] = "no-store"
        return response
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
async def confirm_age_page(request: Request):
    ticket = request.cookies.get(PENDING_COOKIE, "")
    if not pending_sign_in(ticket, "web"):
        return templates.TemplateResponse("confirm_age.html", {
            "request": request, "threshold": ACCOUNT_MIN_AGE, "mode": "account",
            "expired": True, "blocked": False, "error": ""
        }, status_code=410)
    response = templates.TemplateResponse("confirm_age.html", {
        "request": request, "threshold": ACCOUNT_MIN_AGE, "mode": "account",
        "expired": False, "blocked": False, "error": ""
    })
    response.headers["Cache-Control"] = "no-store"
    return response

@qr_app.post("/auth/confirm-age", response_class=HTMLResponse)
async def confirm_age_submit(
    request: Request,
    birth_year: str = Form(""),
    birthday_this_year: str = Form(""),
):
    ticket = request.cookies.get(PENDING_COOKIE, "")
    if not pending_sign_in(ticket, "web"):
        raise HTTPException(status_code=410, detail="Age confirmation expired. Sign in again.")
    try:
        age = age_from_year(birth_year, birthday_this_year)
    except ValueError as exc:
        return templates.TemplateResponse("confirm_age.html", {
            "request": request, "threshold": ACCOUNT_MIN_AGE, "mode": "account",
            "expired": False, "blocked": False, "error": str(exc)
        }, status_code=400)
    pending = consume_sign_in(ticket, "web", age)
    if not pending:
        raise HTTPException(status_code=410, detail="Age confirmation expired. Sign in again.")
    if age < ACCOUNT_MIN_AGE:
        response = templates.TemplateResponse("confirm_age.html", {
            "request": request, "threshold": ACCOUNT_MIN_AGE, "mode": "account",
            "expired": False, "blocked": True, "error": ""
        }, status_code=403)
        response.delete_cookie(PENDING_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
        response.headers["Cache-Control"] = "no-store"
        return response
    user_id, _, session_id = finish_verified_sign_in(pending, request, client_kind="web")
    response = response_after_login(user_id, request, pending["return_to"])
    set_session_cookie(response, session_id)
    if pending["remember_me"]:
        issue_remember_me_cookie(response, user_id, request)
    response.delete_cookie(PENDING_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    return response


@qr_app.post("/auth/confirm-age/mobile")
async def confirm_age_mobile(request: Request, payload: dict = Body(...)):
    # This is a one-time continuation, not a second identity-verification path.
    if not isinstance(payload, dict) or set(payload) != {"ageTicket", "birthYear", "birthdayThisYear"}:
        raise HTTPException(status_code=400, detail="Invalid age confirmation request.")
    ticket = payload.get("ageTicket")
    if not isinstance(ticket, str) or not pending_sign_in(ticket, "mobile"):
        raise HTTPException(status_code=410, detail="Age confirmation expired. Sign in again.")
    try:
        age = age_from_year(payload.get("birthYear"), payload.get("birthdayThisYear"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    pending = consume_sign_in(ticket, "mobile", age)
    if not pending:
        raise HTTPException(status_code=410, detail="Age confirmation expired. Sign in again.")
    if age < ACCOUNT_MIN_AGE:
        raise HTTPException(status_code=403, detail="SafeScan accounts are unavailable below the minimum age.")
    user_id, user, session_id = finish_verified_sign_in(pending, request, client_kind="mobile")
    return mobile_sign_in_body(user_id, user, session_id)


@qr_app.get("/auth/confirm-adult", response_class=HTMLResponse)
async def confirm_adult_page(request: Request, next_url: str = Query("/", alias="next")):
    destination = safe_next_url(request, next_url)
    user = get_session_user(request)
    if (user and account_is_adult(user["google_id"])) or (not user and guest_is_adult(request.cookies.get(GUEST_ADULT_COOKIE, ""))):
        return RedirectResponse(destination, status_code=303)
    ticket = create_adult_challenge(user["google_id"] if user else None, destination)
    response = templates.TemplateResponse("confirm_age.html", {
        "request": request, "threshold": ADULT_MIN_AGE, "mode": "adult",
        "expired": False, "blocked": False, "error": ""
    })
    response.set_cookie(ADULT_CHALLENGE_COOKIE, ticket, max_age=PENDING_SECONDS,
                        httponly=True, secure=True, samesite="lax", path="/")
    response.headers["Cache-Control"] = "no-store"
    return response


@qr_app.post("/auth/confirm-adult", response_class=HTMLResponse)
async def confirm_adult_submit(request: Request, birth_year: str = Form(""),
                               birthday_this_year: str = Form(""), adult_attestation: str = Form("")):
    user = get_session_user(request)
    user_id = user["google_id"] if user else None
    ticket = request.cookies.get(ADULT_CHALLENGE_COOKIE, "")
    try:
        age = age_from_year(birth_year, birthday_this_year)
    except ValueError as exc:
        return templates.TemplateResponse("confirm_age.html", {
            "request": request, "threshold": ADULT_MIN_AGE, "mode": "adult",
            "expired": False, "blocked": False, "error": str(exc)
        }, status_code=400)
    destination = consume_adult_challenge(ticket, user_id)
    if destination is None:
        raise HTTPException(status_code=410, detail="Age confirmation expired. Try again.")
    if age < ADULT_MIN_AGE or adult_attestation != "yes":
        response = templates.TemplateResponse("confirm_age.html", {
            "request": request, "threshold": ADULT_MIN_AGE, "mode": "adult",
            "expired": False, "blocked": True, "error": ""
        }, status_code=403)
    else:
        response = RedirectResponse(destination, status_code=303)
        if user:
            record_adult_attestation(user_id)
        else:
            response.set_cookie(GUEST_ADULT_COOKIE, create_guest_adult_ticket(),
                                max_age=GUEST_ADULT_SECONDS, httponly=True, secure=True,
                                samesite="lax", path="/")
    response.delete_cookie(ADULT_CHALLENGE_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    return response


@qr_app.post("/auth/confirm-adult/mobile")
async def confirm_adult_mobile(request: Request, payload: dict = Body(...)):
    if not isinstance(payload, dict) or set(payload) != {"ageTicket", "birthYear", "birthdayThisYear", "adultAttestation"}:
        raise HTTPException(status_code=400, detail="Invalid adult confirmation request.")
    ticket = payload.get("ageTicket")
    if not isinstance(ticket, str):
        raise HTTPException(status_code=410, detail="Age confirmation expired. Try again.")
    user = get_session_user(request)
    user_id = user["google_id"] if user else None
    try:
        age = age_from_year(payload.get("birthYear"), payload.get("birthdayThisYear"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if consume_adult_challenge(ticket, user_id) is None:
        raise HTTPException(status_code=410, detail="Age confirmation expired. Try again.")
    if age < ADULT_MIN_AGE or payload.get("adultAttestation") is not True:
        raise HTTPException(status_code=403, detail="This feature requires an adult age confirmation.")
    if user:
        record_adult_attestation(user_id)
        return {"adultConfirmed": True}
    response = JSONResponse({"adultConfirmed": True}, headers={"Cache-Control": "no-store"})
    response.set_cookie(GUEST_ADULT_COOKIE, create_guest_adult_ticket(),
                        max_age=GUEST_ADULT_SECONDS, httponly=True, secure=True,
                        samesite="lax", path="/")
    return response

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
async def retired_airdrop_trigger():
    raise HTTPException(status_code=410, detail="This distribution route has been retired.")




# print("Testing URL bad:")
# print(check_url("http://testsafebrowsing.appspot.com/s/malware.html"))

# print("Testing URL good:")
# print(check_url("https://google.com"))


