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
from urllib.parse import quote, urlencode, urljoin, urlparse, parse_qsl
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree

from fastapi import FastAPI, UploadFile, File, Request, Form, Header, Query, Body, HTTPException, Depends
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
from markupsafe import Markup
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
from .csrf import require_csrf_form
from .config import ADMIN_EMAIL
from .config import ADMIN_EMAIL_GMAIL_COMPOSE_URL
from .config import ALPHA_SOLANA_RECIPIENT
from .config import APP_URL
from .config import CLIENT_ID
from .config import LEGAL_LAST_UPDATED
from .config import LEGAL_VERSION
from .config import templates
from .email_util import email_sending_configured
from .email_util import send_email
from .history import index_user_context
from .legal import delete_user_data
from .legal import get_user_export
from .legal import legal_context
from .payments_solana import alpha_solana_pay_url
from .payments_solana import alpha_solana_quote_for_user
from .payments_solana import get_or_create_alpha_solana_reference
from .payments_solana import record_alpha_solana_subscription
from .payments_solana import verify_alpha_solana_payment
from .payments_stripe import alpha_stripe_checkout_url
from .payments_stripe import process_stripe_webhook_event
from .payments_stripe import verify_stripe_webhook_signature
from .referrals import get_scan_count
from .request_helpers import hash_ip
from .request_helpers import locale_from_request
from .request_helpers import make_id
from .request_helpers import request_ip
from .security import enforce_rate_limit
from .security import html_rate_limit_response
from .security import validate_strict_payload
from .wallet import expire_alpha_subscriptions

# =============================================================================
# ROUTES — SERVER-RENDERED HTML PAGES (home, product, legal, account, etc.)
# =============================================================================
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

    from removals.engine import RemovalProfile, run_broker_removal, supported_broker

    broker_config = supported_broker(normalized_broker)
    if broker_config is None:
        raise SafeScanError("Backend automation is not available for this broker yet.", 400)
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

    rate_limited = enforce_rate_limit(request, "go_ghost", 3, 24 * 60 * 60, user_key=user.get("google_id"))
    if rate_limited:
        return rate_limited
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
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Privacy Policy", Markup(PRIVACY_POLICY_HTML)))

@qr_app.post("/waitlist", response_class=HTMLResponse, dependencies=[Depends(require_csrf_form)])
async def waitlist_signup(request: Request, email: str = Form(...)):
    normalized_email = email.strip().lower()
    ip_rate_limit = enforce_rate_limit(request, "waitlist_ip", 3, 60 * 60)
    if ip_rate_limit:
        return html_rate_limit_response(request, ip_rate_limit)
    # The per-address budget uses a separate 24-hour window. Its extra
    # generous IP cap in enforce_rate_limit does not narrow the 3/hour cap.
    address_key = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()
    address_rate_limit = enforce_rate_limit(request, "waitlist_address", 1, 24 * 60 * 60, user_key=address_key)
    if address_rate_limit:
        return html_rate_limit_response(request, address_rate_limit)
    with get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO waitlist_signups VALUES (?, ?, ?)",
            (normalized_email, "footer", datetime.utcnow().isoformat() + "Z")
        )
    # Best-effort welcome email; a no-op unless SMTP_* env vars are configured.
    if email_sending_configured():
        await asyncio.to_thread(
            send_email,
            normalized_email,
            "You're on the SafeScan QR list",
            templates.env.get_template("email/waitlist_welcome.html").render(app_url=APP_URL),
        )
    body = "<h2>You're on the list</h2><p>Thanks for joining the SafeScan QR waitlist. We'll send only major product updates.</p><p><a href='/'>Return to SafeScan QR</a></p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Waitlist", Markup(body)))

@qr_app.get("/legal/terms-of-use", response_class=HTMLResponse)
async def terms_of_use(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Terms of Use", Markup(TERMS_HTML)))

@qr_app.get("/legal/privacy", response_class=HTMLResponse)
async def privacy_policy_alias(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Privacy Policy", Markup(PRIVACY_POLICY_HTML)))

@qr_app.get("/legal/terms", response_class=HTMLResponse)
async def terms_of_use_alias(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Terms of Use", Markup(TERMS_HTML)))

@qr_app.get("/legal/cookie-policy", response_class=HTMLResponse)
async def cookie_policy(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Cookie Policy", Markup(COOKIE_POLICY_HTML)))

@qr_app.get("/legal/terms-history", response_class=HTMLResponse)
async def terms_history(request: Request):
    body = "<h2>Version History</h2><p>v1.0 - May 2026: Initial SafeScan QR Terms of Use.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Terms History", Markup(body)))

@qr_app.get("/changelog", response_class=HTMLResponse)
async def changelog_page(request: Request):
    body = "<h2>Changelog</h2><p>v0.1 - May 2026: SafeScan QR hackathon MVP, risk engine, legal pages, and footer system.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Changelog", Markup(body)))

@qr_app.get("/legal/license", response_class=HTMLResponse)
async def license_page(request: Request):
    body = """
    <h2>License</h2>
    <p>SafeScan QR is currently proprietary while the product is in hackathon and early beta development. Open-source components remain governed by their original licenses.</p>
    <p>Public API, SDK, and mobile client licensing will be published before a production developer release.</p>
    """
    return templates.TemplateResponse("legal_page.html", legal_context(request, "License", Markup(body)))

@qr_app.get("/legal/security", response_class=HTMLResponse)
async def security_page(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(
        request, "Security", content_template="legal/security_body.html",
    ))

@qr_app.get("/contact", response_class=HTMLResponse)
async def contact_page(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(
        request, "Contact", content_template="legal/contact_body.html",
        email_compose_url=ADMIN_EMAIL_GMAIL_COMPOSE_URL,
    ))

@qr_app.get("/product/install", response_class=HTMLResponse)
async def product_install(request: Request):
    body = "<h2>Install</h2><p>SafeScan QR is currently available as a web demo. iOS, Android, and Solana Mobile distribution are planned after the hackathon MVP.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Install", Markup(body)))

@qr_app.get("/product/getting-started", response_class=HTMLResponse)
async def product_getting_started(request: Request):
    body = "<h2>Getting Started</h2><p>Sign in, connect a wallet for airdrop tracking, then scan or paste a QR payload to see the SafeScan risk verdict and signal breakdown.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Getting Started", Markup(body)))

@qr_app.get("/risk-engine", response_class=HTMLResponse)
async def risk_engine_page(request: Request):
    body = """
    <h2>Risk analysis model</h2>
    <p>SafeScan QR turns a QR payload into a 0-100 risk score by decoding the payload, classifying the action, inspecting URLs, checking configured reputation sources, matching wallet-drain patterns, and optionally blending in the local ML model. An incomplete check is reported as unverified. The final verdict describes what SafeScan found at scan time; it is not a guarantee of safety.</p>

    <div class="risk-model-grid">
      <section>
        <h3>Score bands</h3>
        <ul>
          <li><strong>0-34 SAFE:</strong> no major suspicious indicators were found and required checks completed.</li>
          <li><strong>35-79 CAUTION:</strong> suspicious signals or incomplete checks need review.</li>
          <li><strong>80-100 MALICIOUS:</strong> high-risk signals indicate likely phishing, malware, credential theft, or wallet drain behavior.</li>
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
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Risk Engine", Markup(body)))

@qr_app.get("/product/wedges", response_class=HTMLResponse)
async def product_wedges(request: Request):
    body = "<h2>Wedges</h2><p>SafeScan starts with consumer QR safety, expands into Solana Mobile distribution, and grows into a threat-intelligence API for wallets, dApps, and payment providers.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Wedges", Markup(body)))

@qr_app.get("/product/pricing", response_class=HTMLResponse)
async def product_pricing(request: Request):
    body = "<h2>Pricing</h2><p>The SafeScan QR public demo is free during the hackathon. Alpha premium access is $1/mo for early API docs, endpoint access, and merchant QR safety workflows.</p><p><a class='primary-button' href='/pay/alpha'>Pay Now</a></p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Pricing", Markup(body)))

@qr_app.get("/pay/alpha", response_class=HTMLResponse)
async def alpha_payment_page(request: Request):
    expire_alpha_subscriptions()
    user = get_session_user(request)
    stripe_url = alpha_stripe_checkout_url(request)
    solana_url = alpha_solana_pay_url(request)
    solana_quote = alpha_solana_quote_for_user(user) if user and solana_url else None
    return templates.TemplateResponse("legal_page.html", legal_context(
        request, "Alpha Payment", content_template="legal/alpha_payment_body.html",
        user=user, stripe_url=stripe_url, solana_url=solana_url,
        solana_quote=solana_quote, solana_recipient=ALPHA_SOLANA_RECIPIENT,
    ))

@qr_app.post("/pay/alpha/solana/verify", response_class=HTMLResponse, dependencies=[Depends(require_csrf_form)])
async def alpha_solana_payment_verify(request: Request):
    user = require_user(request)
    try:
        quote_row = get_or_create_alpha_solana_reference(user)
        reference = quote_row["reference"] if quote_row else ""
        signature = verify_alpha_solana_payment(reference)
        if not signature:
            return templates.TemplateResponse("legal_page.html", legal_context(
                request, "Solana Payment Pending", content_template="legal/solana_payment_body.html",
                payment_state="pending",
            ), status_code=202)
        record = record_alpha_solana_subscription(user, reference, signature)
    except SafeScanError as exc:
        return templates.TemplateResponse("legal_page.html", legal_context(
            request, "Solana Payment Error", content_template="legal/solana_payment_body.html",
            payment_state="error", error_message=exc.args[0],
        ), status_code=exc.status_code)

    return templates.TemplateResponse("legal_page.html", legal_context(
        request, "Solana Payment Verified", content_template="legal/solana_payment_body.html",
        payment_state="verified", payment_record=record,
    ))

@qr_app.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    verify_stripe_webhook_signature(payload, request.headers.get("stripe-signature", ""))
    try:
        event = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook payload.") from exc
    result = process_stripe_webhook_event(event)
    return {"received": True, "result": result}

@qr_app.get("/pay/alpha/success", response_class=HTMLResponse)
async def alpha_payment_success_page(request: Request):
    expire_alpha_subscriptions()
    return templates.TemplateResponse("legal_page.html", legal_context(
        request, "Alpha Payment Pending", content_template="legal/alpha_success_body.html",
        admin_email=ADMIN_EMAIL,
    ))

@qr_app.get("/resources/docs", response_class=HTMLResponse)
async def resources_docs(request: Request):
    body = "<h2>Docs</h2><p>SafeScan docs will cover QR scanning, risk signals, reputation checks, wallet-pattern detection, and API usage.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Docs", Markup(body)))

@qr_app.get("/resources/architecture", response_class=HTMLResponse)
async def resources_architecture(request: Request):
    body = "<h2>Architecture</h2><p>The risk engine pipeline normalizes QR payloads, checks domain intelligence, traces redirects, runs reputation lookups, matches crypto risk patterns, and merges signals into a verdict.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Architecture", Markup(body)))

@qr_app.get("/resources/roadmap", response_class=HTMLResponse)
async def resources_roadmap(request: Request):
    body = "<h2>Roadmap</h2><p>Next milestones: waitlist, mobile beta, Solana dApp Store submission, wallet integrations, threat-intelligence API, and expanded abuse reporting.</p>"
    return templates.TemplateResponse("legal_page.html", legal_context(request, "Roadmap", Markup(body)))

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
    return templates.TemplateResponse("legal_page.html", legal_context(request, "$SQR Tokenomics", Markup(body)))

@qr_app.get("/legal/do-not-sell", response_class=HTMLResponse)
async def do_not_sell(request: Request):
    return templates.TemplateResponse("legal_page.html", legal_context(
        request, "Do Not Sell or Share", content_template="legal/do_not_sell_body.html",
    ))

@qr_app.get("/legal/data-request", response_class=HTMLResponse)
async def data_request_page(request: Request, email: str = Query("")):
    return templates.TemplateResponse("data_request.html", {
        "request": request, "email": email, "message": "", "export_data": "",
        "version": LEGAL_VERSION, "last_updated": LEGAL_LAST_UPDATED
    })

@qr_app.post("/legal/data-request", response_class=HTMLResponse, dependencies=[Depends(require_csrf_form)])
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
    rate_limited = enforce_rate_limit(request, "consent", 10, 60 * 60)
    if rate_limited:
        return rate_limited
    validate_strict_payload(payload, {"consentType", "bannerVersion"})
    consent_type = payload.get("consentType", "essential_only")
    if not isinstance(consent_type, str) or consent_type not in {"all", "essential_only"}:
        raise SafeScanError("Invalid consent choice.", 400)
    banner_version = payload.get("bannerVersion", "consent-v1")
    if (not isinstance(banner_version, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", banner_version)):
        raise SafeScanError("Invalid banner version.", 400)
    user = get_session_user(request)
    consent_given = consent_type != "essential_only"
    now = datetime.utcnow()
    consent_id = make_id("consent")
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO consent_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                consent_id,
                user.get("google_id") if user else None,
                hash_ip(request_ip(request)),
                int(consent_given),
                consent_type,
                banner_version,
                now.isoformat() + "Z",
                request.headers.get("user-agent", "")[:256],
                locale_from_request(request)[:35],
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
    return templates.TemplateResponse("admin_table.html", {
        "request": request, "title": "Consent Log", "content_template": "admin/consent_log_body.html",
        "rows": rows, "message": "",
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
    audit_log("admin.view_logs", request=request, actor_user_id=admin_user.get("google_id"), target_type="data_processing_log")
    return templates.TemplateResponse("admin_table.html", {
        "request": request, "title": "Data Processing Log",
        "content_template": "admin/data_processing_body.html", "categories": categories, "message": "",
    })

@qr_app.get("/admin/report-breach", response_class=HTMLResponse)
async def report_breach_form(request: Request, secret: str = Query("")):
    require_role_user(request, "admin")
    return templates.TemplateResponse("admin_table.html", {
        "request": request, "title": "Report Breach",
        "content_template": "admin/breach_report_form.html", "message": "",
    })

@qr_app.post("/admin/report-breach", response_class=HTMLResponse, dependencies=[Depends(require_csrf_form)])
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
    return templates.TemplateResponse("admin_table.html", {
        "request": request, "title": "Breach Template",
        "content_template": "admin/breach_template_body.html",
        "report_id": report_id, "report_text": template,
        "message": "Report logged. Connect email provider for live admin notifications.",
    })

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


