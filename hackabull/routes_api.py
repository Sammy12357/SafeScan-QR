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
from .admin_data import airdrop_tier
from .admin_data import next_airdrop_milestone
from .app_module import qr_app
from .audit import SafeScanError
from .audit import audit_log
from .audit import now_iso
from .auth import get_session_user
from .auth import require_role_user
from .auth import require_user
from .config import APP_STARTED_AT
from .config import APP_URL
from .config import MAX_QR_UPLOAD_BYTES
from .fraud import run_fraud_checks
from .heuristics import check_crypto_pattern_signals
from .heuristics import check_domain_intelligence
from .history import group_scan_history
from .history import persist_qr_upload
from .history import save_scan_history
from .history import serialize_scan_history_row
from .pipeline import analyze_full_pipeline
from .qr_decode import decode_qr_upload
from .qr_detect import analyze_embedded_url_payload
from .qr_detect import analyze_qr_payload
from .qr_detect import describe_qr_action
from .qr_detect import detect_payload
from .qr_detect import extract_urls
from .qr_detect import pipeline_response_to_template_analysis
from .qr_image import render_safescan_logo
from .redirects import trace_redirect_chain
from .referrals import get_scan_count
from .referrals import record_unique_scan
from .referrals import referral_code_for_user
from .reputation import google_reputation_signal
from .reputation import virustotal_reputation_signal
from .request_helpers import make_id
from .scoring import signal
from .security import enforce_rate_limit
from .security import validate_public_url
from .security import validate_strict_payload
from .wallet import cleanup_wallet_nonces
from .wallet import get_verified_wallet
from .wallet import is_valid_solana_address
from .wallet import verify_solana_signature
from .wallet import verify_wallet_on_chain
from .wallet import wallet_verification_message

# =============================================================================
# ROUTES — PUBLIC JSON API (/api/*)
# =============================================================================
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

    Runs the URL through the same risk pipeline as `/api/scan` (rule signals
    plus the ML model) and refuses to render the QR when the maliciousness
    score is 90 or higher — so any QR coming out of this endpoint has been
    screened and isn't a likely-malicious link.

    Returns a PNG image with the SafeScan logo overlaid in the centre (high
    error correction tolerates the badge without breaking scanning).
    """
    user = get_session_user(request)
    user_key = user.get("google_id") if user else None
    # Guests on the homepage get 5/hour per IP; signed-in users still get 20/hour
    # under their user key. The analyzer still refuses to render risky URLs.
    limit = 20 if user else 5
    rate_limit = enforce_rate_limit(request, "qr_generate", limit, 60 * 60, user_key=user_key)
    if rate_limit:
        return rate_limit

    validate_strict_payload(payload, {"url"})
    target_url = validate_public_url((payload.get("url") or "").strip())

    analysis = await analyze_full_pipeline(target_url)
    overall_risk = (analysis.get("overallRisk") or "").lower()
    # Maliciousness score (0-100) from the full risk pipeline: rule signals
    # (domain age, redirect chain, reputation, VirusTotal, Safe Browsing,
    # crypto patterns) blended with the ML model score.
    risk_score = int(analysis.get("confidenceScore") or analysis.get("score") or 0)

    # A score of 90 or higher means the link is almost certainly malicious, so
    # SafeScan refuses to mint a QR code for it.
    if risk_score >= 90:
        raise SafeScanError(
            f"This link is likely malicious (risk score {risk_score}/100). "
            "SafeScan won't generate a QR code for it.",
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

    # Centre-overlay the SafeScan logo so recipients can see at a glance that
    # the QR was generated and screened by SafeScan. High error correction
    # (~30% of modules) tolerates a centred overlay without breaking scanning.
    # If the brand asset can't be rendered we fall back to a verified-checkmark
    # badge so generation never fails over a missing/unparseable logo.
    img_w, img_h = img.size
    cx, cy = img_w // 2, img_h // 2
    draw = ImageDraw.Draw(img)
    logo_size = max(64, img_w // 4)
    logo = render_safescan_logo(logo_size)
    if logo is not None:
        # White quiet-zone behind the logo so it reads cleanly against the QR.
        pad = max(6, logo_size // 12)
        radius = max(6, logo_size // 8)
        draw.rounded_rectangle(
            [cx - logo_size // 2 - pad, cy - logo_size // 2 - pad,
             cx + logo_size // 2 + pad, cy + logo_size // 2 + pad],
            radius=radius + pad,
            fill="white",
        )
        img.paste(logo, (cx - logo_size // 2, cy - logo_size // 2), logo)
    else:
        badge_size = max(48, img_w // 5)
        bx = (img_w - badge_size) // 2
        by = (img_h - badge_size) // 2
        pad = 8
        draw.rectangle([bx - pad, by - pad, bx + badge_size + pad, by + badge_size + pad], fill="white")
        draw.rectangle([bx, by, bx + badge_size, by + badge_size], outline="#67f2c8", width=4)
        # Checkmark stroke.
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
        actor_user_id=user.get("google_id") if user else None,
        target_type="url",
        metadata={
            "url": target_url,
            "risk": overall_risk,
            "score": int(analysis.get("confidenceScore") or 0),
            "guest": not bool(user),
        },
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

    history = [serialize_scan_history_row(row) for row in rows]
    if request.query_params.get("grouped", "").lower() in ("1", "true", "yes"):
        return {"items": history, "groups": group_scan_history(history)}
    return history

@qr_app.get("/api/history")
async def api_history(request: Request):
    user = get_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    with get_conn() as conn:
        rows = user_scoped_select(conn, "scan_history")
    rows = sorted(rows, key=lambda row: row["created_at"] or "", reverse=True)[:100]
    result = [serialize_scan_history_row(row) for row in rows]
    if request.query_params.get("grouped", "").lower() in ("1", "true", "yes"):
        return {"items": result, "groups": group_scan_history(result)}
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
        "name": "Safe Scanner",
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
            "name": user.get("display_name") or "Safe Scanner",
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

