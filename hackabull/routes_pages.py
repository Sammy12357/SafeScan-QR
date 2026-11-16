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
import logging
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
from removals.registry import load_brokers
from removals.regions import US_STATES

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration
from .admin_data import COOKIE_POLICY_HTML
from .admin_data import PRIVACY_POLICY_HTML
from .admin_data import TERMS_HTML
from .app_module import qr_app
from .audit import SafeScanError
from .audit import audit_log
from .audit import now_iso
from .auth import get_session_user
from .auth import require_role_user
from .auth import require_user
from .config import ADMIN_EMAIL
from .config import ADMIN_EMAIL_GMAIL_COMPOSE_URL
from .config import ALPHA_SOLANA_RECIPIENT
from .config import ALPHA_SOLANA_ACCESS_DAYS
from .config import APP_URL
from .config import BILLING_LEGAL_ENTITY_NAME
from .config import BILLING_POSTAL_ADDRESS
from .config import BILLING_REFUND_POLICY_TEXT
from .config import BILLING_SUPPORT_EMAIL
from .config import CLIENT_ID
from .config import CONSENT_BANNER_VERSION
from .config import GO_GHOST_BROWSER_AUTOMATION_AVAILABLE
from .config import LEGAL_LAST_UPDATED
from .config import LEGAL_VERSION
from .config import MOCK_MODE
from .config import templates
from .token_flags import token_features_enabled
from .errors import ERRORS
from .errors import request_id_for
from .waitlist_email import confirmation_available
from .waitlist_email import confirmation_send_failed
from .waitlist_email import confirmation_token_valid
from .waitlist_email import confirm_subscription
from .waitlist_email import request_confirmation
from .waitlist_email import send_confirmation
from .waitlist_email import unsubscribe
from .history import index_user_context
from .legal import delete_user_data
from .legal import get_user_export
from .legal import legal_context
from .payments_solana import alpha_solana_pay_url
from .payments_solana import alpha_solana_quote_for_user
from .payments_solana import get_or_create_alpha_solana_reference
from .payments_solana import record_alpha_solana_subscription
from .payments_solana import verify_alpha_solana_payment
from .payments_stripe import billing_identity_ready
from .payments_stripe import billing_terms_text
from .payments_stripe import consume_payment_form_token
from .payments_stripe import create_stripe_checkout
from .payments_stripe import create_stripe_portal
from .payments_stripe import issue_payment_form_token
from .payments_stripe import process_stripe_webhook_event
from .payments_stripe import require_payment_user
from .payments_stripe import send_confirmation_if_pending
from .payments_stripe import stripe_checkout_configured
from .payments_stripe import verify_stripe_webhook_signature
from .referrals import get_scan_count
from .request_helpers import hash_ip
from .request_helpers import locale_from_request
from .request_helpers import make_id
from .request_helpers import request_ip
from .security import enforce_rate_limit
from .security import validate_strict_payload
from .wallet import expire_alpha_subscriptions

# =============================================================================
# ROUTES — SERVER-RENDERED HTML PAGES (home, product, legal, account, etc.)
# =============================================================================
@qr_app.get("/__states", response_class=HTMLResponse, include_in_schema=False)
async def states_gallery(request: Request):
    """Visual QA gallery, inaccessible unless the app runs in mock mode."""
    if not MOCK_MODE:
        raise HTTPException(status_code=404)
    state_fixture = request.query_params.get("__state", "all")
    allowed_fixtures = {
        "all", "empty", "first-use", "no-results", "no-access",
        "loading", "loading-compact", "error", "offline",
        "notice", "info", "success", "warning", "danger", "content",
    }
    if state_fixture not in allowed_fixtures:
        raise HTTPException(status_code=404)
    return templates.TemplateResponse("states_gallery.html", {
        "request": request, "logged_in": False, "state_fixture": state_fixture,
    })


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

@qr_app.get("/api/go-ghost/brokers")
async def api_go_ghost_brokers():
    return JSONResponse({"brokers": load_brokers()}, headers={"Cache-Control": "public, max-age=300"})


@qr_app.get("/go-ghost", response_class=HTMLResponse)
async def go_ghost_page(request: Request):
    user = get_session_user(request)
    account_id = user.get("google_id") if user else ""
    if user and not account_id:
        raise SafeScanError("Go Ghost account identity is unavailable.", 503, code="go_ghost_identity_unavailable")
    response = templates.TemplateResponse("go_ghost.html", {
        "request": request,
        "logged_in": bool(user),
        "email": user["email"] if user else "",
        "go_ghost_brokers": load_brokers(),
        "go_ghost_account_id": account_id,
        "go_ghost_account_name": (user.get("display_name") or "") if user else "",
        "go_ghost_account_email": (user.get("email") or "") if user else "",
        "go_ghost_us_states": US_STATES,
        "browser_automation_available": GO_GHOST_BROWSER_AUTOMATION_AVAILABLE,
        "version": LEGAL_VERSION,
        **index_user_context(user),
    })
    response.headers["Cache-Control"] = "no-store"
    return response

@qr_app.post("/api/go-ghost/removals/{broker}")
async def api_go_ghost_removal(request: Request, broker: str, payload: dict = Body(...)):
    user = require_user(request)
    if not GO_GHOST_BROWSER_AUTOMATION_AVAILABLE:
        raise SafeScanError(
            "Assisted broker submissions are unavailable. Use Search, Opt out, and Copy details to complete the request in your browser.",
            503,
            code="assisted_brokers_unavailable",
        )
    normalized_broker = (broker or "").strip().lower()

    from removals.engine import RemovalProfile, run_broker_removal, supported_broker

    broker_config = supported_broker(normalized_broker)
    if broker_config is None:
        raise SafeScanError(code="broker_unsupported")
    validate_strict_payload(payload, {"name", "address", "cityState", "phone", "email"})

    profile_payload = {
        "name": str(payload.get("name") or "").strip()[:160],
        "address": str(payload.get("address") or "").strip()[:220],
        "city_state": str(payload.get("cityState") or "").strip()[:140],
        "phone": str(payload.get("phone") or "").strip()[:80],
        "email": str(payload.get("email") or "").strip()[:180],
    }
    if not profile_payload["name"]:
        raise SafeScanError(code="profile_name_required", field="name")
    if not profile_payload["email"]:
        raise SafeScanError(code="profile_email_required", field="email")

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
                broker_config.optout_url,
                created_at,
                created_at,
            ),
        )

    try:
        result = await run_broker_removal(normalized_broker, RemovalProfile(**profile_payload))
    except RuntimeError as exc:
        result = {
            "status": "unavailable",
            "detail": str(exc),
            "targetUrl": broker_config.optout_url,
        }
    except Exception as exc:
        result = {
            "status": "failed",
            "detail": f"{broker_config.name} automation failed before submission: {type(exc).__name__}: {str(exc)[:320]}",
            "targetUrl": broker_config.optout_url,
        }

    status = str(result.get("status") or "failed")[:40]
    detail = str(result.get("detail") or "")[:500]
    target_url = str(result.get("targetUrl") or broker_config.optout_url)[:500]
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

def _waitlist_page(request: Request, *, email: str = "", error: str = "", error_field: str = "email", joined: bool = False, status_code: int = 200):
    if joined:
        body = "<h2>Check your email</h2><p>If this address needs confirmation, we sent a link. Product updates begin only after the address is confirmed. If you already confirmed, no action is needed.</p><p><a href='/'>Return to SafeScan QR</a></p>"
    else:
        value = escape_html(email, quote=True)
        error_markup = f"<p class='form-field-error' id='waitlist-email-error' role='alert' data-server-error-focus>{escape_html(error)}</p>" if error else ""
        invalid = " aria-invalid='true' aria-describedby='waitlist-email-error'" if error and error_field == "email" else ""
        consent_invalid = " aria-invalid='true' aria-describedby='waitlist-email-error'" if error and error_field == "consent" else ""
        body = (
            "<h2>Join the waitlist</h2><p>Get an email when SafeScan ships major updates.</p>"
            "<form class='legal-form' action='/waitlist' method='post'>"
            "<label for='waitlist-email'>Email address</label>"
            f"<input id='waitlist-email' name='email' type='email' required value='{value}'{invalid}>"
            "<input type='hidden' name='source' value='waitlist'>"
            f"<label class='waitlist-consent'><input type='checkbox' name='consent' value='yes' required{consent_invalid}>"
            "<span>Send me SafeScan QR product updates. I understand I must confirm by email and can unsubscribe from any update.</span></label>"
            f"{error_markup}<button class='primary-button' type='submit'>Request updates</button></form>"
        )
    context = legal_context(request, "Waitlist", body)
    context["eyebrow"] = "SafeScan QR updates"
    return templates.TemplateResponse("legal_page.html", context, status_code=status_code, headers={"Cache-Control": "no-store"})


@qr_app.get("/waitlist", response_class=HTMLResponse)
async def waitlist_page(request: Request, joined: bool = Query(False)):
    return _waitlist_page(request, joined=joined)


@qr_app.post("/waitlist", response_class=HTMLResponse)
async def waitlist_signup(request: Request, email: str = Form(""), consent: str = Form(""), source: str = Form("waitlist")):
    limited = enforce_rate_limit(request, "waitlist_signup", 12, 60 * 60)
    if limited:
        return limited
    normalized_email = email.strip().lower()
    if len(normalized_email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", normalized_email):
        return _waitlist_page(request, email=normalized_email, error=ERRORS["email_invalid"].message, status_code=400)
    if consent != "yes":
        return _waitlist_page(request, email=normalized_email, error="Select the checkbox to request product updates.", error_field="consent", status_code=400)
    if not confirmation_available():
        return _waitlist_page(request, email=normalized_email, error="Email updates are unavailable right now. Please try again later.", status_code=503)
    token = request_confirmation(normalized_email, source if source in {"footer", "waitlist"} else "waitlist")
    if token and not await asyncio.to_thread(send_confirmation, normalized_email, token):
        confirmation_send_failed(normalized_email, token)
        return _waitlist_page(request, email=normalized_email, error="We could not send the confirmation email. Please try again later.", status_code=503)
    return RedirectResponse("/waitlist?joined=1", status_code=303)


def _waitlist_action_page(request: Request, title: str, body: str, *, status_code: int = 200):
    response = templates.TemplateResponse(
        "legal_page.html", legal_context(request, title, body), status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex"
    return response


@qr_app.get("/waitlist/confirm", response_class=HTMLResponse)
async def waitlist_confirm_page(request: Request, token: str = Query("")):
    if not confirmation_token_valid(token):
        return _waitlist_action_page(request, "Confirm updates", "<h2>Link unavailable</h2><p>This confirmation link is invalid or expired. You can request a new link from the waitlist form.</p>", status_code=410)
    body = (
        "<h2>Confirm product updates</h2>"
        "<p>Confirm that you want SafeScan QR product updates at the address that received the email.</p>"
        "<form class='legal-form' method='post' action='/waitlist/confirm'>"
        f"<input type='hidden' name='token' value='{escape_html(token, quote=True)}'>"
        "<button class='primary-button' type='submit'>Confirm updates</button></form>"
    )
    return _waitlist_action_page(request, "Confirm updates", body)


@qr_app.post("/waitlist/confirm", response_class=HTMLResponse)
async def waitlist_confirm_submit(request: Request, token: str = Form("")):
    limited = enforce_rate_limit(request, "waitlist_confirm", 30, 60 * 60)
    if limited:
        return limited
    if not confirm_subscription(token):
        return _waitlist_action_page(request, "Confirm updates", "<h2>Link unavailable</h2><p>This confirmation link is invalid or expired. You can request a new link from the waitlist form.</p>", status_code=410)
    return _waitlist_action_page(request, "Updates confirmed", "<h2>Updates confirmed</h2><p>You can unsubscribe from any product update.</p>")


def _waitlist_unsubscribe_response(request: Request, token: str):
    if not unsubscribe(token):
        return _waitlist_action_page(request, "Unsubscribe", "<h2>Link unavailable</h2><p>This unsubscribe link is invalid or expired. Contact SafeScan QR to stop updates.</p>", status_code=410)
    return _waitlist_action_page(request, "Unsubscribed", "<h2>Unsubscribed</h2><p>SafeScan QR product updates have been stopped for this address.</p>")


@qr_app.get("/waitlist/unsubscribe", response_class=HTMLResponse)
async def waitlist_unsubscribe_link(request: Request, token: str = Query("")):
    return _waitlist_unsubscribe_response(request, token)


@qr_app.post("/waitlist/unsubscribe", response_class=HTMLResponse)
async def waitlist_unsubscribe_one_click(request: Request, token: str = Query("")):
    # RFC 8058 email clients POST to the URL in List-Unsubscribe. The query
    # carries the bearer token; the POST body does not contain user identity.
    return _waitlist_unsubscribe_response(request, token)

@qr_app.get("/legal/terms-of-use", response_class=HTMLResponse)
async def terms_of_use(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Terms of Use", TERMS_HTML))

@qr_app.get("/legal/privacy", response_class=HTMLResponse)
async def privacy_policy_alias(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Privacy Policy", PRIVACY_POLICY_HTML))

@qr_app.get("/legal/terms", response_class=HTMLResponse)
async def terms_of_use_alias(request: Request):
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


@qr_app.get("/accessibility", response_class=HTMLResponse)
async def accessibility_page(request: Request):
    """State the accessibility target and current verification limits."""
    contact = escape_html(ADMIN_EMAIL, quote=True)
    body = f"""
    <h2>Our target</h2>
    <p>SafeScan is working toward <a href="https://www.w3.org/TR/WCAG22/" target="_blank" rel="noopener noreferrer">WCAG 2.2 Level AA</a> for the website. This is a target, not a claim that every page and feature conforms.</p>
    <h2>What we check</h2>
    <p>Automated checks cover public pages in dark and light mode. We also review keyboard access, focus movement, text alternatives, and scanner controls. Automated checks cannot find every accessibility problem.</p>
    <h2>Known issues and verification gaps</h2>
    <ul>
      <li>Some pages still need clearer main landmarks and a more consistent heading order for assistive navigation.</li>
      <li>Screen reader behavior across all device and browser combinations has not had a complete independent audit.</li>
      <li>Camera hardware, third-party sign-in and payment handoffs, and the separate mobile app need continued manual testing.</li>
      <li>New content and integrations may introduce issues before they are found and corrected.</li>
    </ul>
    <h2>Report a barrier</h2>
    <p>If you cannot use part of SafeScan, email <a href="mailto:{contact}">{contact}</a> or use our <a href="/contact">contact page</a>. Tell us the page, what you were trying to do, and your device or assistive technology if you are comfortable sharing it. We will review the report and work with you on another way to get the information or complete the task.</p>
    """
    context = legal_context(request, "Accessibility", body)
    context.update({"eyebrow": "Accessibility", "version": "1.0", "last_updated": "November 15, 2026"})
    return templates.TemplateResponse("legal_page.html", context)

@qr_app.get("/contact", response_class=HTMLResponse)
async def contact_page(request: Request):
    body = f"""
    <section class="contact-hero">
      <h2>Contact Sqafe (SafeScan QR)</h2>
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
    body = "<h2>Getting Started</h2><p>Scan or paste a QR payload to see SafeScan's risk explanation. Sign in to review scan history.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Getting Started", body))

@qr_app.get("/risk-engine", response_class=HTMLResponse)
async def risk_engine_page(request: Request):
    body = """
    <h2>Risk analysis model</h2>
    <p>SafeScan QR turns a QR payload into a 0-100 risk score by decoding the payload, classifying the action, inspecting URLs, checking configured reputation sources, matching wallet-drain patterns, and optionally blending in the local ML model. An incomplete check is reported as unverified. The final verdict describes what SafeScan found at scan time; it is not a guarantee of safety.</p>

    <div class="risk-model-grid">
      <section>
        <h3>Score bands</h3>
        <ul>
          <li><strong>0-34 Lower risk score:</strong> completed checks found no known threat match at scan time; a link may change later.</li>
          <li><strong>35-79 Needs review:</strong> suspicious signals or incomplete checks need independent review.</li>
          <li><strong>80-100 High-risk indicators:</strong> signals may indicate phishing, malware, credential theft, or wallet drain behavior.</li>
        </ul>
      </section>
      <section>
        <h3>Output data</h3>
        <ul>
          <li>Final verdict, risk score, threat class, and check coverage.</li>
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
          <li>Google Web Risk threat matches when configured (or Safe Browsing in eligible noncommercial setups).</li>
          <li>A locally matched PhishTank feed of verified, active phishing URLs.</li>
          <li>A visible incomplete-check state when a reputation or redirect lookup is unavailable.</li>
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
      <li><strong>Score:</strong> convert each signal into weighted risk, then clamp the final risk score from 0 to 100.</li>
      <li><strong>Blend ML:</strong> when enabled, combine the local QR ML model score with rule-based evidence.</li>
      <li><strong>Explain:</strong> return the verdict, score, reasons, action description, threat class, and optional admin/reporting metadata.</li>
    </ol>

    <h2>Stored data</h2>
    <p>For signed-in users, SafeScan can save scan history and counters so profile progress, scan history, fraud prevention, and leaderboard features work across sessions permanently unless deletion is requested or the account is removed. Stored scan rows may include user id, email, URL or payload, risk score, verdict, signal JSON, report status, and created time. Uploaded QR image files may be stored temporarily according to the configured upload retention policy.</p>

    <h2>Privacy and limits</h2>
    <p>URL payloads may be sent to configured reputation providers. SafeScan shows what checks completed, but a URL with no known threat match can still be harmful or change after the scan. Verify important links, wallet prompts, and payment recipients independently.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Risk Engine", body))

@qr_app.get("/product/wedges", response_class=HTMLResponse)
async def product_wedges(request: Request):
    body = "<h2>Wedges</h2><p>SafeScan starts with consumer QR safety, expands into Solana Mobile distribution, and grows into a threat-intelligence API for wallets, dApps, and payment providers.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Wedges", body))

@qr_app.get("/product/pricing", response_class=HTMLResponse)
async def product_pricing(request: Request):
    body = "<h2>Pricing</h2><p>The SafeScan QR public demo is free. Alpha Premium card billing is US$1 per month and renews monthly until canceled. Solana is a separate one-time access option.</p><p><a class='primary-button' href='/pay/alpha'>View payment terms</a></p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Pricing", body))

@qr_app.get("/pay/alpha", response_class=HTMLResponse)
async def alpha_payment_page(request: Request):
    expire_alpha_subscriptions()
    user = get_session_user(request)
    if user:
        user = require_payment_user(request)
    stripe_ready = stripe_checkout_configured()
    stripe_token = issue_payment_form_token(user, "stripe_checkout") if user and stripe_ready else ""
    terms = escape_html(billing_terms_text())
    business = (
        f"<p class='payment-note'>Seller: {escape_html(BILLING_LEGAL_ENTITY_NAME)} · "
        f"{escape_html(BILLING_POSTAL_ADDRESS)} · "
        f"Support: {escape_html(BILLING_SUPPORT_EMAIL)}</p>"
        if billing_identity_ready() else
        "<p class='payment-note'>Checkout is paused while business and refund details are verified.</p>"
    )
    stripe_button = (
        """<form action='/pay/alpha/stripe/checkout' method='post'>
            <label><input type='checkbox' name='recurring_consent' value='yes' required>
              I agree to recurring monthly billing on the terms shown above.</label>
            <input type='hidden' name='payment_token' value='""" + escape_html(stripe_token) + """'>
            <button class='primary-button payment-button stripe-payment-button' type='submit'>Continue to Stripe checkout</button>
          </form>"""
        if stripe_token else
        "<p class='payment-note'>Sign in to pay by card. Card checkout remains unavailable until verified billing settings are configured.</p>"
    )
    solana_url = alpha_solana_pay_url(request) if user and billing_identity_ready() else ""
    solana_quote = alpha_solana_quote_for_user(user) if user and solana_url else None
    solana_token = issue_payment_form_token(user, "solana_verify") if user and solana_url else ""
    solana_verify = (
        """<form action="/pay/alpha/solana/verify" method="post">
          <input type='hidden' name='payment_token' value='""" + escape_html(solana_token) + """'>
          <button class="secondary-button payment-button" type="submit">Verify Solana payment</button>
        </form>"""
        if solana_token else
        "<p class='payment-note'>Sign in before paying with Solana; payment must be attached to your account.</p>"
    )
    solana_button = (
        f"<a class='secondary-button payment-button' href='{escape_html(solana_url, quote=True)}'>Pay with Solana</a>"
        if solana_url else
        "<span class='secondary-button payment-button payment-disabled'>Solana checkout is unavailable right now</span>"
    )
    solana_note = (
        (
            f"<p class='payment-note'>Quote: ${solana_quote['amountUsd']} = {solana_quote['amountSol']} SOL"
            + (f" at ${solana_quote['solUsdPrice']}/SOL" if solana_quote.get("solUsdPrice") else " using fallback SOL pricing")
            + f". Valid until {solana_quote['quoteExpiresAt']}.</p>"
            + f"<p class='payment-note'>Solana payment recipient: <code>{ALPHA_SOLANA_RECIPIENT}</code></p>"
        )
        if solana_quote else
        f"<p class='payment-note'>Solana payment recipient: <code>{ALPHA_SOLANA_RECIPIENT}</code></p>"
        if ALPHA_SOLANA_RECIPIENT else
        "<p class='payment-note'>Solana checkout is unavailable right now. Use card checkout or return later.</p>"
    )
    body = f"""
    <h2>Alpha Premium</h2>
    <p>Alpha access includes Go Ghost privacy cleanup, SafeScan QR premium API docs, risk scoring endpoints, and merchant QR safety workflows.</p>
    <div class="payment-panel">
      <div class="payment-option">
        <p class="eyebrow">Card</p>
        <h3>Monthly subscription</h3>
        <p>{terms}</p>
        <p>Manage or cancel from <a href='/profile'>Profile → Billing</a>.</p>
        {stripe_button}
      </div>
      <div class="payment-option payment-option-wallet">
        <h3>Wallet payment</h3>
        <p>Solana is a one-time payment for {ALPHA_SOLANA_ACCESS_DAYS} days of Alpha access. It does not renew. {escape_html(BILLING_REFUND_POLICY_TEXT)}</p>
        {solana_button}
        {solana_verify}
        {solana_note}
      </div>
    </div>
    {business}
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Alpha Payment", body))

@qr_app.post("/pay/alpha/stripe/checkout")
async def alpha_stripe_checkout(request: Request, recurring_consent: str = Form(""), payment_token: str = Form("")):
    user = require_payment_user(request)
    rate_limited = enforce_rate_limit(request, "stripe_checkout", 5, 3600, user_key=user["google_id"])
    if rate_limited:
        return rate_limited
    consume_payment_form_token(user, "stripe_checkout", payment_token)
    if recurring_consent != "yes":
        raise HTTPException(status_code=400, detail="You must agree to recurring monthly billing before checkout.")
    url = await asyncio.to_thread(create_stripe_checkout, user)
    return RedirectResponse(url, status_code=303)

@qr_app.get("/pay/alpha/manage")
async def alpha_stripe_manage(request: Request):
    # Cancellation stays available even if a later age check closes new sales.
    user = require_user(request)
    rate_limited = enforce_rate_limit(request, "stripe_portal", 20, 3600, user_key=user["google_id"])
    if rate_limited:
        return rate_limited
    url = await asyncio.to_thread(create_stripe_portal, user)
    return RedirectResponse(url, status_code=303)

@qr_app.post("/pay/alpha/solana/verify", response_class=HTMLResponse)
async def alpha_solana_payment_verify(request: Request, payment_token: str = Form("")):
    user = require_payment_user(request)
    rate_limited = enforce_rate_limit(request, "solana_verify", 10, 3600, user_key=user["google_id"])
    if rate_limited:
        return rate_limited
    consume_payment_form_token(user, "solana_verify", payment_token)
    try:
        quote_row = get_or_create_alpha_solana_reference(user)
        reference = quote_row["reference"] if quote_row else ""
        signature = verify_alpha_solana_payment(reference)
        if not signature:
            body = """
            <h2>Solana payment not found yet</h2>
            <p>SafeScan could not find a confirmed Solana payment for your payment reference yet. If you just paid, wait a few seconds and try verification again.</p>
            <p><a class="primary-button payment-button" href="/pay/alpha">Back to Alpha payment</a></p>
            """
            return templates.TemplateResponse("legal_page.html", legal_context(request, "Solana Payment Pending", body), status_code=202)
        record = record_alpha_solana_subscription(user, reference, signature)
    except SafeScanError as exc:
        if exc.status_code >= 500:
            logging.getLogger("safescan.errors").error(json.dumps({
                "event": "solana_verification_failed",
                "request_id": request_id_for(request),
                "method": request.method,
                "route": "/pay/alpha/solana/verify",
                "exception_type": type(exc).__name__,
                "status_code": exc.status_code,
                "code": exc.code,
            }))
        entry = ERRORS.get(exc.code or "") if exc.status_code < 500 else ERRORS.get(exc.code or "", ERRORS["payment_unavailable"])
        public_message = entry.message if entry else str(exc)
        public_hint = entry.hint if entry else "Open the payment page and try again."
        body = f"<h2>Solana verification unavailable</h2><p role='alert'>{escape_html(public_message)} {escape_html(public_hint)}</p><p><a class='primary-button payment-button' href='/pay/alpha'>Back to Alpha payment</a></p>"
        return templates.TemplateResponse("legal_page.html", legal_context(request, "Solana Payment Error", body), status_code=exc.status_code)

    body = f"""
    <h2>Solana payment verified</h2>
    <p>Alpha access is active for {record['email']} until {record['expires_at']}.</p>
    <p class="payment-note">Transaction signature: <code>{record['signature']}</code></p>
    <p><a class="primary-button payment-button" href="/resources/docs">Open docs</a></p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Solana Payment Verified", body))

@qr_app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    verify_stripe_webhook_signature(payload, request.headers.get("stripe-signature", ""))
    try:
        event = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook payload.") from exc
    result = await asyncio.to_thread(process_stripe_webhook_event, event)
    if result.get("session_id"):
        await asyncio.to_thread(send_confirmation_if_pending, result["session_id"])
    return {"received": True, "result": result}

@qr_app.get("/pay/alpha/success", response_class=HTMLResponse)
async def alpha_payment_success_page(request: Request):
    expire_alpha_subscriptions()
    body = """
    <h2>Checkout return</h2>
    <p>SafeScan is checking the signed payment confirmation from Stripe. This page does not activate access. Check your profile for current billing status.</p>
    <div class="payment-panel">
      <div>
        <p class="eyebrow">Billing</p>
        <h3>Review your account</h3>
        <a class="primary-button payment-button" href="/profile">Open profile</a>
      </div>
      <div>
        <p class="eyebrow">Alpha docs</p>
        <h3>Product information</h3>
        <p>Review the Alpha docs while payment confirmation is pending.</p>
        <a class="primary-button payment-button" href="/resources/docs">Open docs</a>
      </div>
    </div>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Checkout Return", body))

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
    if not token_features_enabled():
        body = "<h2>Token features are not available</h2><p>SafeScan's QR scanner and risk explanations remain available.</p><p><a href='/#scanner'>Scan a QR code</a></p>"
        return templates.TemplateResponse("legal_page.html", legal_context(request, "Token features unavailable", body))
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
        "region": "", "request_type": "access", "details": "", "field_errors": {},
        "version": LEGAL_VERSION, "last_updated": LEGAL_LAST_UPDATED
    }, headers={"Cache-Control": "no-store"})

@qr_app.post("/legal/data-request", response_class=HTMLResponse)
async def submit_data_request(
    request: Request,
    email: str = Form(""),
    region: str = Form(""),
    request_type: str = Form(""),
    details: str = Form("")
):
    email = email.strip().lower()
    region = region.strip()
    details = details.strip()
    allowed_types = {
        "access", "erasure", "rectification", "restriction", "portability",
        "object", "do_not_sell", "limit_sensitive", "revoke_consent",
    }
    field_errors = {}
    if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        field_errors["email"] = "Enter a valid email address."
    if len(region) > 100:
        field_errors["region"] = "Use 100 characters or fewer for the region."
    if request_type not in allowed_types:
        field_errors["request_type"] = "Choose the type of request."
    if len(details) > 5000:
        field_errors["details"] = "Use 5,000 characters or fewer for the details."
    if field_errors:
        return templates.TemplateResponse("data_request.html", {
            "request": request, "email": email, "region": region,
            "request_type": request_type, "details": details,
            "message": "", "export_data": "", "field_errors": field_errors,
            "version": LEGAL_VERSION, "last_updated": LEGAL_LAST_UPDATED,
        }, status_code=400, headers={"Cache-Control": "no-store"})
    request_id = make_id("dsr")
    now = datetime.utcnow().isoformat() + "Z"
    export_data = ""
    status = "submitted"
    session_user = get_session_user(request)
    verified_self_request = session_user and session_user.get("email") == email.strip().lower()
    if request_type in ("access", "portability"):
        if verified_self_request:
            export = get_user_export(session_user["email"], session_user.get("google_id"))
            if export is not None:
                export_data = json.dumps(export, indent=2)
                status = "completed"
    elif request_type == "erasure":
        if verified_self_request:
            if delete_user_data(session_user["email"], session_user.get("google_id")):
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

    message = f"Request {request_id} recorded. Keep this reference for your records."
    if verified_self_request and request_type in ("access", "portability", "erasure") and status == "submitted":
        message = f"Request {request_id} recorded. Account ownership needs review before this request can be completed."
        if request_type == "erasure":
            with get_conn() as conn:
                billing_record = conn.execute(
                    """SELECT 1 FROM alpha_subscriptions WHERE user_id = ? AND provider = 'stripe'
                       UNION SELECT 1 FROM stripe_checkout_intents WHERE user_id = ? LIMIT 1""",
                    (session_user["google_id"], session_user["google_id"]),
                ).fetchone()
            if billing_record:
                message = f"Request {request_id} recorded for billing-record review. If you have an active card subscription, cancel it from Profile → Billing; your account remains available while this request is reviewed."
    return templates.TemplateResponse("data_request.html", {
        "request": request, "email": email, "region": region,
        "request_type": request_type, "details": details, "field_errors": {},
        "message": message, "export_data": export_data,
        "version": LEGAL_VERSION, "last_updated": LEGAL_LAST_UPDATED
    }, headers={"Cache-Control": "no-store"})

@qr_app.post("/api/consent")
async def log_consent(request: Request, payload: dict = Body(...)):
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid consent choice.")
    consent_type = payload.get("consentType", "essential_only")
    if not isinstance(consent_type, str) or consent_type not in {"all", "custom", "essential_only"}:
        raise HTTPException(status_code=400, detail="Invalid consent choice.")
    if payload.get("bannerVersion") != CONSENT_BANNER_VERSION:
        raise HTTPException(status_code=409, detail="Refresh the page before saving your privacy choice.")
    if request.headers.get("sec-gpc", "").strip() == "1":
        consent_type = "essential_only"
    session_user = get_session_user(request)
    consent_given = consent_type != "essential_only"
    now = datetime.utcnow()
    consent_id = make_id("consent")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO consent_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                consent_id,
                session_user["google_id"] if session_user else None,
                hash_ip(request_ip(request)),
                int(consent_given),
                consent_type,
                CONSENT_BANNER_VERSION,
                now.isoformat() + "Z",
                request.headers.get("user-agent", ""),
                locale_from_request(request),
                (now + timedelta(days=365)).isoformat() + "Z"
            )
        )
    return {"id": consent_id, "expiresInDays": 365, "effectiveConsentType": consent_type}

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
    return templates.TemplateResponse("admin_table.html", {
        "request": request, "title": "Consent Log", "body_html": body, "message": "",
        "empty_state_title": "No consent records yet" if not rows else "",
        "empty_state_body": "Consent decisions will appear here when they are recorded.",
    })

@qr_app.get("/admin/data-processing-log", response_class=HTMLResponse)
async def data_processing_log(request: Request, secret: str = Query("")):
    admin_user = require_role_user(request, "admin")
    categories = [
        ("OAuth profile", "Authentication", "Contractual necessity", "Google, Render", "Until deletion or 2 years inactivity"),
        ("QR payload URLs", "Risk analysis, scan history, and leaderboard records", "Legitimate interest", "Google Web Risk when configured; AI provider if enabled; PhishTank feed checked locally", "Long-term account record until deletion is requested or account is removed"),
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
    return templates.TemplateResponse("admin_table.html", {
        "request": request, "title": "Report Breach", "breach_form": True,
        "form_values": {}, "field_errors": {}, "message": "",
    })

@qr_app.post("/admin/report-breach", response_class=HTMLResponse)
async def report_breach(
    request: Request,
    discovery_date: str = Form(""),
    data_categories: str = Form(""),
    users_affected: str = Form(""),
    likely_consequences: str = Form(""),
    measures_taken: str = Form("")
):
    admin_user = require_role_user(request, "admin")
    values = {
        "discovery_date": discovery_date.strip(),
        "data_categories": data_categories.strip(),
        "users_affected": users_affected.strip(),
        "likely_consequences": likely_consequences.strip(),
        "measures_taken": measures_taken.strip(),
    }
    errors = {}
    try:
        datetime.fromisoformat(values["discovery_date"].replace("Z", "+00:00"))
    except ValueError:
        errors["discovery_date"] = "Enter the discovery date as an ISO date or timestamp."
    if not values["data_categories"] or len(values["data_categories"]) > 2000:
        errors["data_categories"] = "Describe the affected data in 2,000 characters or fewer."
    if not values["users_affected"] or len(values["users_affected"]) > 80:
        errors["users_affected"] = "Enter an estimate or say unknown, in 80 characters or fewer."
    if not values["likely_consequences"] or len(values["likely_consequences"]) > 4000:
        errors["likely_consequences"] = "Describe likely consequences in 4,000 characters or fewer."
    if not values["measures_taken"] or len(values["measures_taken"]) > 4000:
        errors["measures_taken"] = "Describe measures taken in 4,000 characters or fewer."
    if errors:
        return templates.TemplateResponse("admin_table.html", {
            "request": request, "title": "Report Breach", "breach_form": True,
            "form_values": values, "field_errors": errors, "message": "",
        }, status_code=400, headers={"Cache-Control": "no-store"})
    discovery_date, data_categories, users_affected, likely_consequences, measures_taken = values.values()
    template = f"""GDPR Article 33/34 Breach Notification Draft\nDiscovery date: {discovery_date}\nData categories affected: {data_categories}\nEstimated users affected: {users_affected}\nLikely consequences: {likely_consequences}\nMeasures taken: {measures_taken}\nAdmin contact: {ADMIN_EMAIL}\nReview whether supervisory authority notice is required within 72 hours and whether user notice is required for high-risk impact."""
    report_id = make_id("breach")
    now = datetime.utcnow().isoformat() + "Z"
    with get_conn() as conn:
        conn.execute("INSERT INTO breach_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (report_id, discovery_date, data_categories, users_affected, likely_consequences, measures_taken, now, template))
    audit_log("admin.breach_report_created", request=request, actor_user_id=admin_user.get("google_id"), target_type="breach_report", target_id=report_id)
    body = f"<h2>Breach Report {escape_html(report_id)}</h2><pre class='legal-json'>{escape_html(template)}</pre>"
    return templates.TemplateResponse("admin_table.html", {"request": request, "title": "Breach Template", "body_html": body, "message": "Report logged. Keep this record for incident review."}, headers={"Cache-Control": "no-store"})

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


