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
    canonical_email_key,
    clear_rls_context,
    database_path,
    database_storage_status,
    get_conn,
    rls_user_id,
    set_rls_context,
    unique_email_owner,
    user_scoped_select,
)
from storage import backend_status as storage_backend_status
from storage import download_file as storage_download_file
from storage import object_key as storage_object_key
from storage import upload_bytes as storage_upload_bytes

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration
from .admin_data import admin_context
from .admin_data import dashboard_data
from .admin_data import fetch_admin_users
from .admin_data import fetch_airdrop_data
from .admin_data import fetch_audit_logs
from .admin_data import fetch_fraud_data
from .admin_data import fetch_reports
from .admin_data import fetch_scans
from .admin_data import fetch_user_detail
from .admin_data import fetch_waitlist
from .app_module import qr_app
from .audit import audit_log
from .audit import now_iso
from .auth import has_role
from .auth import require_role_user
from .config import ADMIN_EMAILS
from .config import APP_URL
from .config import OWNER_EMAILS
from .config import VALID_ROLES
from .config import templates
from .errors import ERRORS
from .history import admin_avatar
from .pipeline import analyze_full_pipeline
from .request_helpers import make_id
from .token_flags import token_distribution_enabled, token_features_enabled
from .payments_stripe import consume_payment_form_token, issue_payment_form_token
from .age_gate import account_is_adult

# =============================================================================
# ROUTES — ADMIN CONSOLE (/admin/*)  [staff only]
# =============================================================================
def _admin_form_error(request, title, page, data, code, *, target="", field="", values=None, owner_only=False):
    entry = ERRORS[code]
    data = dict(data)
    if page == "users":
        data.setdefault("filters", {"search": target, "status": "", "role": "", "tier": "", "flag": ""})
    data["form_error"] = {
        "message": entry.message,
        "hint": entry.hint,
        "target": target,
        "field": field,
        "submitted": values or {},
    }
    return admin_context(request, title, page, data, owner_only=owner_only, status_code=entry.status_code)


def _single_email_account_id(conn, email: str) -> str:
    """Resolve legacy email actions only when one canonical account owns it."""
    # SELECT alone does not hold a write transaction in sqlite3. Lock before
    # checking uniqueness so an account cannot appear before the later UPDATE.
    conn.execute("BEGIN IMMEDIATE")
    key = canonical_email_key(email)
    if key is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    matches = [(row[0], row[1]) for row in conn.execute(
        "SELECT google_id, email FROM users WHERE email IS NOT NULL"
    ) if canonical_email_key(row[1]) == key]
    if not matches:
        raise HTTPException(status_code=404, detail="Account not found.")
    if len(matches) != 1 or not unique_email_owner(conn, matches[0][1], matches[0][0]):
        raise HTTPException(status_code=409, detail="This email belongs to more than one account.")
    return matches[0][0]


def _require_one_account_updated(cursor) -> None:
    if cursor.rowcount != 1:
        raise HTTPException(status_code=409, detail="Account action was not applied.")


def _admin_account_error(request, title, page, data_factory, exc, *, target, values=None):
    if exc.status_code not in (404, 409):
        raise exc
    code = "admin_account_missing" if exc.status_code == 404 else "admin_account_ambiguous"
    return _admin_form_error(
        request, title, page, data_factory(), code,
        target=target, field="account", values=values,
    )


@qr_app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    return admin_context(request, "Dashboard", "dashboard", dashboard_data())

@qr_app.get("/admin/activity", response_class=HTMLResponse)
async def admin_activity(request: Request):
    return admin_context(request, "Activity Feed", "logs", fetch_audit_logs())

@qr_app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, search: str = Query(""), status: str = Query(""), role: str = Query(""), tier: str = Query(""), page: int = Query(1), flag: str = Query("")):
    data = fetch_admin_users(search=search, status=status, role=role, tier=tier, page=page, flag=flag)
    data.update({"filters": {"search": search, "status": status, "role": role, "tier": tier, "flag": flag}})
    return admin_context(request, "All Users", "users", data)

def _admin_user_detail_page(request: Request, reference: str):
    admin_user = require_role_user(request, "admin")
    data = fetch_user_detail(reference)
    if not data["user"]:
        raise HTTPException(status_code=404, detail="Not found.")
    return templates.TemplateResponse("admin_shell.html", {"request": request, "page": "user_drawer", "title": "User Detail", "data": data, "admin_user": admin_user, "is_owner": has_role(admin_user, "owner"), "avatar": admin_avatar(admin_user.get("email"))})


@qr_app.get("/admin/users/detail", response_class=HTMLResponse)
async def admin_user_detail(request: Request, account_id: str = Query(...)):
    return _admin_user_detail_page(request, account_id)


@qr_app.get("/admin/users/{email}/drawer", response_class=HTMLResponse)
async def admin_user_drawer(request: Request, email: str):
    return _admin_user_detail_page(request, email)

@qr_app.post("/admin/users/{email}/suspend")
async def admin_suspend_user(request: Request, email: str, action: str = Form("suspend")):
    admin_user = require_role_user(request, "admin")
    if action not in ("suspend", "unsuspend"):
        return _admin_form_error(request, "All Users", "users", fetch_admin_users(search=email), "admin_action_invalid", target=email, field="action")
    new_status = "active" if action == "unsuspend" else "suspended"
    try:
        with get_conn() as conn:
            account_id = _single_email_account_id(conn, email)
            _require_one_account_updated(conn.execute("UPDATE users SET status = ? WHERE google_id = ?", (new_status, account_id)))
    except HTTPException as exc:
        return _admin_account_error(request, "All Users", "users", lambda: fetch_admin_users(search=email), exc, target=email, values={"action": action})
    audit_log("admin.user_unsuspended" if new_status == "active" else "admin.user_suspended", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=account_id)
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.post("/admin/users/{email}/role")
async def admin_change_role(request: Request, email: str, role: str = Form("")):
    admin_user = require_role_user(request, "owner")
    if role not in VALID_ROLES:
        return _admin_form_error(request, "All Users", "users", fetch_admin_users(search=email), "admin_action_invalid", target=email, field="role", values={"role": role})
    try:
        with get_conn() as conn:
            account_id = _single_email_account_id(conn, email)
            _require_one_account_updated(conn.execute("UPDATE users SET role = ? WHERE google_id = ?", (role, account_id)))
    except HTTPException as exc:
        return _admin_account_error(request, "All Users", "users", lambda: fetch_admin_users(search=email), exc, target=email, values={"role": role})
    audit_log("admin.role_changed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=account_id, metadata={"role": role})
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.post("/admin/users/{email}/delete")
async def admin_delete_user(request: Request, email: str, confirm: str = Form("")):
    admin_user = require_role_user(request, "owner")
    if confirm != "DELETE":
        return _admin_form_error(request, "All Users", "users", fetch_admin_users(search=email), "admin_delete_confirmation", target=email, field="confirm", values={"confirm": confirm})
    try:
        with get_conn() as conn:
            account_id = _single_email_account_id(conn, email)
            _require_one_account_updated(conn.execute("UPDATE users SET status = 'deleted', deleted_at = ?, airdrop_status = 'disqualified' WHERE google_id = ?", (now_iso(), account_id)))
    except HTTPException as exc:
        return _admin_account_error(request, "All Users", "users", lambda: fetch_admin_users(search=email), exc, target=email, values={"confirm": confirm})
    audit_log("admin.user_deleted", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=account_id)
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
    rows = [row for row in fetch_waitlist(limit=5000)["rows"] if row.get("status") == "confirmed"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["email", "source", "created_at", "confirmed_at", "consent_version"])
    writer.writeheader()
    for row in rows:
        record = {}
        for key in writer.fieldnames:
            value = str(row.get(key) or "")
            record[key] = "'" + value if value.startswith(("=", "+", "-", "@", "\t", "\r")) else value
        writer.writerow(record)
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
        if not str(scan["url"] or "").lower().startswith(("https://", "http://")):
            return _admin_form_error(request, "All Scans", "scans", fetch_scans(), "admin_non_url_scan", target=scan_id)
        conn.execute("UPDATE scan_history SET verdict = 'MALICIOUS', risk_score = 100 WHERE id = ?", (scan_id,))
        conn.execute("INSERT OR IGNORE INTO url_blocklist VALUES (?, ?, ?, ?, ?, NULL)", (make_id("block"), scan["url"], "Admin confirmed malicious scan", admin_user.get("email"), now_iso()))
    audit_log("admin.url_flagged", request=request, actor_user_id=admin_user.get("google_id"), target_type="scan", target_id=scan_id)
    return RedirectResponse("/admin/scans", status_code=303)

@qr_app.get("/admin/reports", response_class=HTMLResponse)
async def admin_reports(request: Request, tab: str = Query("reports")):
    return admin_context(request, "Reported URLs", "reports", fetch_reports(tab=tab))

@qr_app.post("/admin/reports/{report_id}/action")
async def admin_report_action(request: Request, report_id: str, action: str = Form("")):
    admin_user = require_role_user(request, "admin")
    if action not in ("confirm", "dismiss", "reanalyze"):
        return _admin_form_error(request, "Reported URLs", "reports", fetch_reports(), "admin_action_invalid", target=report_id, field="action")
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
    if not token_features_enabled():
        return admin_context(request, "Token features unavailable", "airdrop_unavailable", {})
    data = fetch_airdrop_data()
    user = require_role_user(request, "admin")
    if token_distribution_enabled() and has_role(user, "owner") and account_is_adult(user["google_id"]):
        data["distribution_form_token"] = issue_payment_form_token(user, "airdrop_distribute")
    return admin_context(request, "Tier Overview", "airdrop", data)

@qr_app.post("/admin/airdrop/distribute", response_class=HTMLResponse)
async def admin_airdrop_distribute(request: Request, distribution_token: str = Form("")):
    admin_user = require_role_user(request, "owner")
    if not token_distribution_enabled():
        raise HTTPException(status_code=503, detail="Token distribution is unavailable.")
    if not account_is_adult(admin_user["google_id"]):
        raise HTTPException(status_code=403, detail="Adult confirmation is required for token distribution.")
    consume_payment_form_token(admin_user, "airdrop_distribute", distribution_token)
    try:
        from distribute import airdrop_sweep
        result = await airdrop_sweep(owner_authorized=True)
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
    if not token_features_enabled():
        return admin_context(request, "Token features unavailable", "airdrop_unavailable", {})
    data = fetch_airdrop_data()
    user = require_role_user(request, "admin")
    if token_distribution_enabled() and has_role(user, "owner") and account_is_adult(user["google_id"]):
        data["distribution_form_token"] = issue_payment_form_token(user, "airdrop_distribute")
    return admin_context(request, "Wallet Registry", "airdrop", data)

@qr_app.post("/admin/airdrop/{email}/status")
async def admin_airdrop_status(request: Request, email: str, status: str = Form(""), reason: str = Form("")):
    admin_user = require_role_user(request, "admin")
    if not token_features_enabled():
        raise HTTPException(status_code=503, detail="Token features are unavailable.")
    if status not in ("eligible", "flagged", "disqualified", "cleared"):
        return _admin_form_error(request, "Tier Overview", "airdrop", fetch_airdrop_data(), "admin_action_invalid", target=email, field="status", values={"reason": reason})
    try:
        with get_conn() as conn:
            account_id = _single_email_account_id(conn, email)
            _require_one_account_updated(conn.execute("UPDATE users SET airdrop_status = ? WHERE google_id = ?", (status, account_id)))
    except HTTPException as exc:
        return _admin_account_error(request, "Tier Overview", "airdrop", fetch_airdrop_data, exc, target=email, values={"status": status, "reason": reason})
    audit_log("admin.airdrop_status_changed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=account_id, metadata={"status": status, "reason": reason})
    return RedirectResponse("/admin/airdrop", status_code=303)

@qr_app.post("/admin/fraud/{email}/review")
async def admin_fraud_review(request: Request, email: str, outcome: str = Form(""), reason: str = Form("")):
    admin_user = require_role_user(request, "admin")
    if outcome not in ("cleared", "disqualified", "escalated"):
        return _admin_form_error(request, "Fraud Flags", "fraud", fetch_fraud_data(), "admin_action_invalid", target=email, field="outcome", values={"reason": reason})
    status = "cleared" if outcome == "cleared" else ("disqualified" if outcome == "disqualified" else "flagged")
    try:
        with get_conn() as conn:
            account_id = _single_email_account_id(conn, email)
            _require_one_account_updated(conn.execute("UPDATE users SET airdrop_status = ? WHERE google_id = ?", (status, account_id)))
            conn.create_function("canonical_email_key", 1, canonical_email_key, deterministic=True)
            conn.execute(
                "UPDATE fraud_flags SET reviewed = 1, reviewed_by = ?, reviewed_at = ?, review_outcome = ? "
                "WHERE reviewed = 0 AND (user_id = ? OR (canonical_email_key(user_id) = ? "
                "AND user_id NOT IN (SELECT google_id FROM users)))",
                (admin_user.get("email"), now_iso(), outcome, account_id, canonical_email_key(email)),
            )
    except HTTPException as exc:
        return _admin_account_error(request, "Fraud Flags", "fraud", fetch_fraud_data, exc, target=email, values={"outcome": outcome, "reason": reason})
    audit_log("admin.fraud_reviewed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=account_id, metadata={"outcome": outcome, "reason": reason})
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
    return admin_context(request, "API Keys", "api_keys", {"keys": _admin_api_key_rows()}, owner_only=True)


def _admin_api_key_rows():
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC")]

@qr_app.post("/admin/api-keys")
async def admin_create_api_key(request: Request, name: str = Form(""), scopes: list[str] = Form([]), expires_at: str = Form("")):
    owner = require_role_user(request, "owner")
    name = name.strip()
    expires_at = expires_at.strip()
    values = {"name": name, "scopes": scopes, "expires_at": expires_at}
    if not name or len(name) > 80:
        return _admin_form_error(request, "API Keys", "api_keys", {"keys": _admin_api_key_rows()}, "api_key_name_required", field="name", values=values, owner_only=True)
    if set(scopes) - {"risk:analyze", "admin:export", "admin:api_keys"}:
        return _admin_form_error(request, "API Keys", "api_keys", {"keys": _admin_api_key_rows()}, "api_key_scope_invalid", field="scopes", values=values, owner_only=True)
    if expires_at:
        try:
            datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return _admin_form_error(request, "API Keys", "api_keys", {"keys": _admin_api_key_rows()}, "api_key_expiry_invalid", field="expires_at", values=values, owner_only=True)
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

