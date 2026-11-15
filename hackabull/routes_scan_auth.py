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

from fastapi import FastAPI, UploadFile, File, Request, Form, Header, Query, Body, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
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
from .accounts import email_account_exists
from .accounts import hash_password
from .accounts import response_after_login
from .accounts import safe_next_url
from .accounts import save_local_user
from .accounts import save_user_to_db
from .accounts import set_user_username
from .accounts import verify_password
from .age_gate import ACCOUNT_MIN_AGE
from .age_gate import PENDING_COOKIE
from .age_gate import PENDING_SECONDS
from .age_gate import begin_sign_in
from .age_gate import eligible_account
from .age_gate import record_account_eligibility
from .app_module import qr_app
from .audit import SafeScanError
from .audit import audit_log
from .audit import now_iso
from .auth import create_session
from .auth import get_session_user
from .auth import request_session_id
from .auth import require_user
from .auth import require_user_from_google_id
from .auth0 import _decode_jwt_unverified
from .auth0 import verify_auth0_id_token
from .config import APP_URL
from .config import AUTH0_ISSUER
from .config import CLIENT_ID
from .config import LEGAL_VERSION
from .config import LOCAL_AUTH_ENABLED
from .config import MAX_QR_UPLOAD_BYTES
from .config import templates
from .errors import ERRORS
from .discord_link import DISCORD_BOT_TOKEN
from .discord_link import DISCORD_CLIENT_ID
from .discord_link import DISCORD_GUILD_ID
from .discord_link import DISCORD_INVITE_URL
from .discord_link import discord_exchange_code
from .discord_link import discord_fetch_identity
from .discord_link import discord_grant_verified_role
from .discord_link import discord_join_guild
from .discord_link import discord_linking_configured
from .discord_link import discord_redirect_uri
from .discord_link import discord_state_for_user
from .discord_link import get_discord_link
from .discord_link import verify_discord_state
from .fraud import run_fraud_checks
from .history import index_user_context
from .payload_privacy import scan_storage_reference
from .history import save_scan_history
from .homograph import host_forms
from .pipeline import analyze_full_pipeline
from .qr_decode import QR_DECODE_SEMAPHORE
from .qr_decode import QRDecodeAmbiguityError
from .qr_decode import QRDecodeSafetyError
from .qr_decode import decode_qr_upload
from .qr_detect import analyze_qr_payload
from .qr_detect import detect_payload
from .qr_detect import pipeline_response_to_template_analysis
from .referrals import get_scan_count
from .referrals import record_unique_scan
from .request_helpers import make_id
from .scoring import risk_reason
from .scoring import signal
from .security import enforce_rate_limit
from .security import validate_public_url
from .security import validate_strict_payload
from .sessions import clear_remember_me_cookie
from .sessions import clear_session_cookie
from .sessions import issue_remember_me_cookie
from .sessions import revoke_all_remember_me
from .sessions import set_session_cookie
from .sessions import wants_remember_me
from .wallet import get_verified_wallet
from .token_flags import token_features_enabled

# =============================================================================
# ROUTES — QR SCANNING & AUTHENTICATION (sign-in, logout, profile, scanning)
# =============================================================================
PROFILE_NOTICES = {
    "discord_cancelled": "Discord linking was cancelled. Start again if you still want to link it.",
    "discord_expired": "Discord linking expired. Start again from your profile.",
    "discord_rejected": "Discord did not accept the link request. Try linking again.",
    "discord_no_id": "We couldn't confirm the Discord account. Try linking again.",
    "discord_duplicate": "That Discord account is already linked to another SafeScan account.",
}


@qr_app.post("/search_qr_api", response_class=HTMLResponse)
async def scan_qr(
    request: Request,
    user_email: str = Form(""),
    wallet_address: str = Form(""),
    device_fingerprint: str = Form(""),
    file: UploadFile = File(None),
    manual_url: str = Form(None),
    template_variant: str = Form(""),
    capture_source: str = Form("")
):
    if capture_source not in ("", "camera_frame"):
        raise SafeScanError(code="invalid_request")
    if capture_source == "camera_frame" and (not file or not file.filename or manual_url):
        raise SafeScanError(code="invalid_request")
    if manual_url is not None and len(manual_url) > 4096:
        raise SafeScanError(code="qr_payload_too_large", field="manual_url")
    user = get_session_user(request)
    user_email = user["email"] if user else ""
    test_site = template_variant in ("main_site", "test_site")
    test_site_path = template_variant == "test_site"
    verified_wallet = get_verified_wallet(user_email) if user_email and token_features_enabled() else None
    wallet_address = verified_wallet["address"] if verified_wallet else ""
    url_qr = None
    qr_image_for_ml = None
    decode_error = None

    if manual_url and manual_url.strip():
        url_qr = manual_url
    elif file and file.filename:
        # Camera frames are decoded from this request only. Do not add a
        # storage artifact here, even for an authenticated scanner.
        contents = await file.read(MAX_QR_UPLOAD_BYTES + 1)
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
        try:
            async with QR_DECODE_SEMAPHORE:
                url_qr, qr_image_for_ml = await run_in_threadpool(
                    decode_qr_upload, contents, file.filename, file.content_type
                )
        except (QRDecodeAmbiguityError, QRDecodeSafetyError) as exc:
            decode_error = str(exc)

    if not url_qr:
        return templates.TemplateResponse("index.html", {
            "request": request, "logged_in": True, "results_visible": True,
            "status": "ERROR", "url_found": decode_error or "No QR code or valid payload detected.",
            "source": "Scanner", "score": "0", "threat_class": "N/A",
            "overall_risk": "suspicious",
            "verdict_summary": decode_error or "SafeScan could not decode a QR payload from this file.",
            "reputation": {"provider": "Scanner", "status": "ERROR", "matches": [], "detail": decode_error or "No decodable payload was found."},
            "risk_reasons": [risk_reason("Ambiguous QR upload" if decode_error else "No QR payload decoded", "medium", decode_error or "Upload a clearer image, SVG, or PDF containing a QR code, or paste the destination manually.")],
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
        # A non-URL QR may contain secrets in any field. Do not submit
        # URL-shaped text from it to external reputation or redirect services.
        analysis = analyze_qr_payload(url_qr)
        analysis["normalized"] = url_qr
    analysis["rawPayload"] = url_qr
    if qr_image_for_ml is not None:
        qr_image_for_ml.close()
    counted = False
    if user_email:
        counted = record_unique_scan(user_email, url_qr, wallet_address, user_id=user.get("google_id") if user else None, payload_type=payload_type)
        save_scan_history(user_email, analysis["normalized"], analysis, user_id=user.get("google_id") if user else None)
        # Fraud velocity is keyed by email, so its private fingerprint uses
        # the same owner identity across scans and later cleanup migrations.
        stored_reference = scan_storage_reference(url_qr, user_email, payload_type)
        run_fraud_checks("scan", user_email, request, {"url": stored_reference, "deviceFingerprint": device_fingerprint})
    audit_log("qr.scanned", request=request, actor_user_id=user.get("google_id") if user else None, target_type="scan", metadata={"counted": counted, "payloadType": payload_type, "guest": not bool(user_email), "cameraFrame": capture_source == "camera_frame"})

    result_response = templates.TemplateResponse("index.html", {
        "request": request, "logged_in": True, "results_visible": True,
        "status": analysis["status"], "url_found": analysis["normalized"], "source": analysis["source"],
        "raw_payload": url_qr,
        "payload_type": analysis.get("payload_type", payload_type),
        "host_forms": host_forms(analysis["normalized"]) if payload_type == "URL" else None,
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
        "fast_path": analysis.get("fastPath"),
        "verification_status": analysis.get("verificationStatus"),
        "unverified_checks": analysis.get("unverifiedChecks", []),
        "optional_checks": analysis.get("optionalChecks", []),
        "email": user_email, "scan_count": get_scan_count(user_email) if user_email else 0, "google_client_id": CLIENT_ID,
        "test_site": test_site,
        "test_site_path": test_site_path,
        "version": LEGAL_VERSION,
        **index_user_context(user)
    })
    result_response.headers["Cache-Control"] = "no-store"
    result_response.headers["Pragma"] = "no-cache"
    return result_response

def finish_verified_sign_in(identity, request, *, client_kind):
    """Create an account and session only after a verified age decision."""
    subject = identity["subject"]
    email = identity["email"]
    try:
        eligible_account(identity["provider"], subject, email)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        user_id = save_user_to_db(subject, email, request, identity.get("display_name") or "",
                                  identity.get("picture") or "", strict_identity=True)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    record_account_eligibility(user_id)
    user = require_user_from_google_id(user_id)
    if user["status"] != "active":
        raise HTTPException(status_code=401, detail="Authentication required.")
    run_fraud_checks("signup", email, request, {"googleId": user_id, "client": client_kind, "provider": identity["provider"]})
    session_id = create_session(user_id, request)
    audit_log("user.login", request=request, actor_user_id=user_id, metadata={"client": client_kind, "provider": identity["provider"]})
    return user_id, user, session_id


def mobile_sign_in_body(user_id, user, session_id):
    return {
        "session": session_id,
        "user": {
            "id": user_id,
            "name": user.get("display_name") or "Safe Scanner",
            "email": user["email"],
            "avatarUrl": user.get("picture"),
            "role": user.get("role", "user"),
        },
    }


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
        email_claim = idinfo["email"]
        if not isinstance(google_id, str) or not google_id or not isinstance(email_claim, str):
            raise ValueError("Invalid identity claims.")
        user_email = email_claim.strip().lower()
        if not user_email:
            raise ValueError("Missing email.")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidSignature):
        audit_log("auth.failed", request=request, metadata={"provider": "google"})
        raise HTTPException(status_code=401, detail="Authentication required.")

    if idinfo.get("email_verified") is False:
        raise HTTPException(status_code=401, detail="Verified email required.")
    identity = {"provider": "google", "subject": google_id, "email": user_email,
                "display_name": idinfo.get("name") if isinstance(idinfo.get("name"), str) else "",
                "picture": idinfo.get("picture") if isinstance(idinfo.get("picture"), str) else ""}
    try:
        ticket = begin_sign_in("google", google_id, user_email, identity["display_name"], identity["picture"],
                               client_kind="web", return_to=return_to, remember=wants_remember_me(remember_me))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if ticket:
        response = RedirectResponse("/auth/confirm-age", status_code=303)
        response.set_cookie(PENDING_COOKIE, ticket, max_age=PENDING_SECONDS, httponly=True,
                            secure=True, samesite="lax", path="/")
        response.headers["Cache-Control"] = "no-store"
        return response
    google_id, user, session_id = finish_verified_sign_in(identity, request, client_kind="web")
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
            # Match the existing web Google identity only for Auth0's Google
            # connection. Other Auth0 connections retain a namespaced subject.
            raw_sub = idinfo.get("sub") or ""
            if not isinstance(raw_sub, str):
                raise ValueError("Auth0 token has an invalid subject.")
            if raw_sub.startswith("google-oauth2|"):
                google_id = raw_sub.split("|", 1)[1]
            else:
                google_id = "auth0:" + raw_sub
            if not google_id:
                raise ValueError("Auth0 token missing subject.")
            email_claim = idinfo.get("email") or ""
            if not isinstance(email_claim, str):
                raise ValueError("Auth0 token has an invalid email.")
            user_email = email_claim.strip().lower()
            if not user_email:
                raise ValueError("Auth0 token missing email.")
        else:
            idinfo = id_token.verify_oauth2_token(credential, google_requests.Request(), CLIENT_ID)
            google_id = idinfo["sub"]
            email_claim = idinfo["email"]
            if not isinstance(google_id, str) or not google_id or not isinstance(email_claim, str):
                raise ValueError("Invalid identity claims.")
            user_email = email_claim.strip().lower()
            if not user_email:
                raise ValueError("Missing email.")
    except (ValueError, KeyError, TypeError, AttributeError, InvalidSignature):
        audit_log("auth.failed", request=request, metadata={"provider": provider})
        raise HTTPException(status_code=401, detail="Authentication required.")

    if idinfo.get("email_verified") is False:
        raise HTTPException(status_code=401, detail="Verified email required.")
    identity = {"provider": provider, "subject": google_id, "email": user_email,
                "display_name": idinfo.get("name") if isinstance(idinfo.get("name"), str) else "",
                "picture": idinfo.get("picture") if isinstance(idinfo.get("picture"), str) else ""}
    try:
        ticket = begin_sign_in(provider, google_id, user_email, identity["display_name"], identity["picture"],
                               client_kind="mobile", remember=False)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if ticket:
        return JSONResponse({"ageConfirmationRequired": True, "ageTicket": ticket,
                             "minimumAge": ACCOUNT_MIN_AGE, "expiresInSeconds": PENDING_SECONDS},
                            status_code=202, headers={"Cache-Control": "no-store"})
    google_id, user, session_id = finish_verified_sign_in(identity, request, client_kind="mobile")
    return mobile_sign_in_body(google_id, user, session_id)

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

@qr_app.get("/auth/discord")
async def auth_discord_start(request: Request):
    """Kick off the Discord OAuth flow for the signed-in user."""
    user = require_user(request)
    if not discord_linking_configured():
        raise SafeScanError(code="discord_unavailable")
    rate_limit = enforce_rate_limit(request, "discord_link", 10, 60 * 60, user_key=user.get("google_id"))
    if rate_limit:
        return rate_limit
    # guilds.join lets us add the user to the server automatically, but only
    # works when a bot token + guild id are configured. Otherwise just identify.
    scope = "identify guilds.join" if (DISCORD_BOT_TOKEN and DISCORD_GUILD_ID) else "identify"
    params = urlencode({
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": discord_redirect_uri(),
        "response_type": "code",
        "scope": scope,
        "state": discord_state_for_user(user["google_id"]),
        "prompt": "consent",
    })
    return RedirectResponse(f"https://discord.com/oauth2/authorize?{params}", status_code=302)

@qr_app.get("/auth/discord/callback")
async def auth_discord_callback(request: Request, code: str = Query(""), state: str = Query(""), error: str = Query("")):
    """Complete the OAuth flow: store the link, then best-effort join + role."""
    user = require_user(request)
    if error or not code:
        return RedirectResponse("/profile?discord_error=discord_cancelled", status_code=303)
    state_user = verify_discord_state(state)
    if not state_user or str(state_user) != str(user.get("google_id")):
        audit_log("discord.link_state_mismatch", request=request, actor_user_id=user.get("google_id"))
        return RedirectResponse("/profile?discord_error=discord_expired", status_code=303)
    try:
        token_payload = await asyncio.to_thread(discord_exchange_code, code)
        identity = await asyncio.to_thread(discord_fetch_identity, token_payload.get("access_token", ""))
    except Exception:
        return RedirectResponse("/profile?discord_error=discord_rejected", status_code=303)
    discord_id = str(identity.get("id") or "")
    discord_username = str(identity.get("username") or "")[:80]
    if not discord_id:
        return RedirectResponse("/profile?discord_error=discord_no_id", status_code=303)

    joined = await asyncio.to_thread(discord_join_guild, discord_id, token_payload.get("access_token", ""))
    role_granted = await asyncio.to_thread(discord_grant_verified_role, discord_id)

    try:
        with get_conn() as conn:
            conn.execute(
                """INSERT INTO discord_links (id, user_id, discord_id, discord_username, guild_member, role_granted, linked_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET
                     discord_id = excluded.discord_id,
                     discord_username = excluded.discord_username,
                     guild_member = excluded.guild_member,
                     role_granted = excluded.role_granted,
                     linked_at = excluded.linked_at""",
                (make_id("dlink"), str(user["google_id"]), discord_id, discord_username, 1 if joined else 0, 1 if role_granted else 0, now_iso()),
            )
    except sqlite3.IntegrityError:
        # discord_id UNIQUE tripped: that Discord account is already linked to
        # a different SafeScan account (anti-abuse for airdrop perks).
        audit_log("discord.link_duplicate", request=request, actor_user_id=user.get("google_id"), metadata={"discordId": discord_id})
        return RedirectResponse("/profile?discord_error=discord_duplicate", status_code=303)

    audit_log("discord.linked", request=request, actor_user_id=user.get("google_id"),
              metadata={"discordId": discord_id, "guildMember": joined, "roleGranted": role_granted})
    return RedirectResponse("/profile", status_code=303)

@qr_app.post("/auth/discord/unlink")
async def auth_discord_unlink(request: Request):
    """Remove the stored Discord link (does not kick them from the server)."""
    user = require_user(request)
    with get_conn() as conn:
        conn.execute("DELETE FROM discord_links WHERE user_id = ?", (str(user["google_id"]),))
    audit_log("discord.unlinked", request=request, actor_user_id=user.get("google_id"))
    return RedirectResponse("/profile", status_code=303)

@qr_app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = Query(""), tab: str = Query("login"), next_url: str = Query("/", alias="next")):
    user = get_session_user(request)
    return_to = safe_next_url(request, next_url)
    if user:
        return RedirectResponse(return_to, status_code=303)
    return templates.TemplateResponse("login.html", _auth_form_context(request, error=error, tab=tab, next_url=return_to))


def _auth_form_context(request, *, error="", error_field="", tab="login", next_url="/", email=""):
    return {
        "request": request,
        "error": error,
        "error_field": error_field,
        "tab": tab,
        "next_url": safe_next_url(request, next_url),
        "form_email": email,
        "local_auth_enabled": LOCAL_AUTH_ENABLED,
        "google_client_id": CLIENT_ID or "",
        "auth_google_url": f"{APP_URL}/auth/google",
    }


def _auth_form_error(request, code, *, tab, next_url, email="", status_code=None, error_field=""):
    entry = ERRORS[code]
    context = _auth_form_context(
        request, error=f"{entry.message} {entry.hint}", error_field=error_field,
        tab=tab, next_url=next_url, email=email,
    )
    return templates.TemplateResponse("login.html", context, status_code=status_code or entry.status_code)

def require_local_auth_enabled():
    if not LOCAL_AUTH_ENABLED:
        raise HTTPException(status_code=404, detail="Not found.")


@qr_app.post("/auth/register", response_class=HTMLResponse, dependencies=[Depends(require_local_auth_enabled)])
async def auth_register(request: Request, email: str = Form(...), password: str = Form(...), remember_me: str = Form("1"), next_url: str = Form("/", alias="next")):
    rate_limited = enforce_rate_limit(request, "register", 5, 3600)
    if rate_limited:
        return rate_limited
    if get_session_user(request):
        return _auth_form_error(request, "already_signed_in", tab="register", next_url=next_url)
    email = email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return _auth_form_error(request, "email_invalid", tab="register", next_url=next_url, email=email, error_field="email")
    if len(password) < 8:
        return _auth_form_error(request, "password_too_short", tab="register", next_url=next_url, email=email, error_field="password")
    if email_account_exists(email):
        return _auth_form_error(request, "account_exists", tab="register", next_url=next_url, email=email, error_field="email")
    lid = save_local_user(email, request)
    # Local password auth is unavailable in production. Keep developer
    # fixtures usable while public Google/Auth0 accounts use the age flow.
    record_account_eligibility(lid)
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO local_credentials (email, password_hash, created_at, user_id) VALUES (?, ?, ?, ?)",
                (email, hash_password(password), now_iso(), lid)
            )
    except sqlite3.IntegrityError:
        return _auth_form_error(request, "account_exists", tab="register", next_url=next_url, email=email, error_field="email")
    run_fraud_checks("signup", email, request, {})
    session_id = create_session(lid, request)
    audit_log("user.register", request=request, actor_user_id=lid)
    response = response_after_login(lid, request, next_url)
    set_session_cookie(response, session_id)
    if wants_remember_me(remember_me):
        issue_remember_me_cookie(response, lid, request)
    return response

@qr_app.post("/auth/login", response_class=HTMLResponse, dependencies=[Depends(require_local_auth_enabled)])
async def auth_login_local(request: Request, email: str = Form(...), password: str = Form(...), remember_me: str = Form("1"), next_url: str = Form("/", alias="next")):
    rate_limited = enforce_rate_limit(request, "login_local", 10, 600)
    if rate_limited:
        return rate_limited
    email = email.strip().lower()
    with get_conn() as conn:
        row = conn.execute("SELECT password_hash, user_id FROM local_credentials WHERE email = ?", (email,)).fetchone()
    if not row or not verify_password(password, row[0]):
        audit_log("auth.failed", request=request, metadata={"provider": "local"})
        return _auth_form_error(request, "credentials_invalid", tab="login", next_url=next_url, email=email)
    lid = save_local_user(email, request)
    record_account_eligibility(lid)
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
    record_account_eligibility(google_id)
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
    return RedirectResponse(f"/profile?error={quote(error)}" if error in ERRORS else "/profile", status_code=303)

@qr_app.post("/onboarding/username", response_class=HTMLResponse)
async def username_onboarding_submit(request: Request, username: str = Form(...)):
    return await profile_username_submit(request, username)

@qr_app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request, error: str = Query(""), discord_error: str = Query("")):
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
        "error": f"{ERRORS[error].message} {ERRORS[error].hint}" if error in ERRORS else "",
        "discord_enabled": discord_linking_configured(),
        "discord_link": get_discord_link(user["google_id"]),
        "discord_error": PROFILE_NOTICES.get(discord_error, ""),
        "discord_invite": DISCORD_INVITE_URL,
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
            "entered_username": username,
            "scan_count": get_scan_count(user.get("email")),
            "leaderboard_status": "Live" if (user.get("username") or "").strip() else "Hidden",
            "error": f"{str(exc)} {exc.hint or ''}".strip(),
            "discord_enabled": discord_linking_configured(),
            "discord_link": get_discord_link(user["google_id"]),
            "discord_error": "",
            "discord_invite": DISCORD_INVITE_URL,
        }, status_code=400)
    audit_log("user.username_set", request=request, actor_user_id=user["google_id"])
    destination = "/" if request.url.path == "/onboarding/username" else "/profile"
    return RedirectResponse(destination, status_code=303)

