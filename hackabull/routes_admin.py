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
from .csrf import require_csrf_form
from .config import APP_URL
from .csrf import require_same_origin_action
from .config import VALID_ROLES
from .config import templates
from .history import admin_avatar
from .pipeline import analyze_full_pipeline
from .request_helpers import make_id

# =============================================================================
# ROUTES — ADMIN CONSOLE (/admin/*)  [staff only]
# =============================================================================
_ROLE_LEVEL = {"user": 1, "admin": 2, "owner": 3}


def _current_admin_actor(conn, user_id, minimum_role):
    """Recheck the actor under the write lock, so a demotion cannot race an action."""
    actor = conn.execute(
        "SELECT google_id, role, status FROM users WHERE google_id = ?", (user_id,)
    ).fetchone()
    if not actor or actor["status"] != "active" or _ROLE_LEVEL.get(actor["role"], 0) < _ROLE_LEVEL[minimum_role]:
        raise HTTPException(status_code=403, detail="You do not have permission to do this.")
    return actor


def _admin_target(conn, identifier):
    """Resolve an email or account ID to exactly one immutable account ID."""
    matches = conn.execute(
        "SELECT google_id, role, status FROM users WHERE email = ? OR google_id = ?",
        (identifier, identifier),
    ).fetchall()
    if not matches:
        raise HTTPException(status_code=404, detail="Not found.")
    if len(matches) != 1:
        raise HTTPException(status_code=409, detail="Select one account by its ID.")
    return matches[0]


def _require_lower_role(actor, target):
    if _ROLE_LEVEL.get(target["role"], 0) >= _ROLE_LEVEL[actor["role"]]:
        raise HTTPException(status_code=403, detail="You cannot change an account with an equal or higher role.")


def _require_another_active_owner(conn, target_id):
    remaining = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'owner' AND status = 'active' AND google_id != ?",
        (target_id,),
    ).fetchone()[0]
    if not remaining:
        raise HTTPException(status_code=409, detail="At least one active owner must remain.")


def _safe_csv_cell(value):
    """Keep untrusted export fields from being interpreted as spreadsheet formulas."""
    if value is None:
        return ""
    cell = str(value)
    if cell.startswith(("\t", "\r", "\n")) or cell.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + cell
    return cell


@qr_app.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    return admin_context(request, "Dashboard", "dashboard", dashboard_data)

@qr_app.get("/admin/activity", response_class=HTMLResponse)
async def admin_activity(request: Request):
    return admin_context(request, "Activity Feed", "logs", fetch_audit_logs)

@qr_app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(request: Request, search: str = Query(""), status: str = Query(""), role: str = Query(""), tier: str = Query(""), page: int = Query(1), flag: str = Query("")):
    def load_data():
        data = fetch_admin_users(search=search, status=status, role=role, tier=tier, page=page)
        data.update({"filters": {"search": search, "status": status, "role": role, "tier": tier, "flag": flag}})
        if flag == "review":
            data["rows"] = [row for row in data["rows"] if row.get("fraud_flags")]
        return data

    return admin_context(request, "All Users", "users", load_data)

@qr_app.get("/admin/users/{email}/drawer", response_class=HTMLResponse)
async def admin_user_drawer(request: Request, email: str):
    admin_user = require_role_user(request, "admin")
    data = fetch_user_detail(email)
    if not data["user"]:
        raise HTTPException(status_code=404, detail="Not found.")
    return templates.TemplateResponse("admin_shell.html", {"request": request, "page": "user_drawer", "title": "User Detail", "data": data, "admin_user": admin_user, "is_owner": has_role(admin_user, "owner"), "avatar": admin_avatar(admin_user.get("email"))})

@qr_app.post("/admin/users/{email}/suspend", dependencies=[Depends(require_csrf_form)])
async def admin_suspend_user(request: Request, email: str, action: str = Form("suspend")):
    admin_user = require_role_user(request, "admin")
    if action not in ("suspend", "unsuspend"):
        raise HTTPException(status_code=400, detail="Invalid request.")
    new_status = "active" if action == "unsuspend" else "suspended"
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        actor = _current_admin_actor(conn, admin_user["google_id"], "admin")
        target = _admin_target(conn, email)
        _require_lower_role(actor, target)
        if target["status"] == "deleted":
            raise HTTPException(status_code=409, detail="Deleted accounts cannot be restored here.")
        conn.execute("UPDATE users SET status = ? WHERE google_id = ?", (new_status, target["google_id"]))
    audit_log("admin.user_unsuspended" if new_status == "active" else "admin.user_suspended", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=target["google_id"])
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.post("/admin/users/{email}/role", dependencies=[Depends(require_csrf_form)])
async def admin_change_role(request: Request, email: str, role: str = Form(...)):
    admin_user = require_role_user(request, "owner")
    if role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid request.")
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        actor = _current_admin_actor(conn, admin_user["google_id"], "owner")
        target = _admin_target(conn, email)
        target_user_id = target["google_id"]
        if target["status"] == "deleted":
            raise HTTPException(status_code=409, detail="Deleted accounts cannot be changed here.")
        if target["role"] == "owner" and role != "owner":
            if target_user_id != actor["google_id"]:
                raise HTTPException(status_code=403, detail="An owner cannot demote another owner.")
            if target["status"] == "active":
                _require_another_active_owner(conn, target_user_id)
        conn.execute("UPDATE users SET role = ? WHERE google_id = ?", (role, target_user_id))
    audit_log("admin.role_changed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=target_user_id, metadata={"role": role})
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.post("/admin/users/{email}/delete", dependencies=[Depends(require_csrf_form)])
async def admin_delete_user(request: Request, email: str, confirm: str = Form("")):
    admin_user = require_role_user(request, "owner")
    if confirm != "DELETE":
        raise HTTPException(status_code=400, detail="Invalid request.")
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        actor = _current_admin_actor(conn, admin_user["google_id"], "owner")
        target = _admin_target(conn, email)
        _require_lower_role(actor, target)
        conn.execute("UPDATE users SET status = 'deleted', deleted_at = ?, airdrop_status = 'disqualified' WHERE google_id = ?", (now_iso(), target["google_id"]))
    audit_log("admin.user_deleted", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=target["google_id"])
    return RedirectResponse("/admin/users", status_code=303)

@qr_app.get("/admin/export/users")
async def admin_export_users(request: Request):
    admin_user = require_role_user(request, "owner")
    users = fetch_admin_users(limit=10000)["rows"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["email", "role", "status", "tier", "scan_count", "referral_count", "wallet_address", "created_at", "last_login_at"])
    writer.writeheader()
    for row in users:
        writer.writerow({key: _safe_csv_cell(row.get(key, "")) for key in writer.fieldnames})
    audit_log("admin.export", request=request, actor_user_id=admin_user.get("google_id"), target_type="users")
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=safescan-users.csv"})

@qr_app.get("/admin/scans", response_class=HTMLResponse)
async def admin_scans(request: Request, search: str = Query(""), verdict: str = Query(""), user: str = Query("")):
    return admin_context(request, "All Scans", "scans", lambda: fetch_scans(search=search, verdict=verdict, user=user))

@qr_app.get("/admin/waitlist", response_class=HTMLResponse)
async def admin_waitlist(request: Request, search: str = Query("")):
    return admin_context(request, "Waitlist", "waitlist", lambda: fetch_waitlist(search=search))

@qr_app.get("/admin/export/waitlist")
async def admin_export_waitlist(request: Request):
    owner = require_role_user(request, "owner")
    rows = fetch_waitlist(limit=5000)["rows"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["email", "source", "created_at"])
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _safe_csv_cell(row.get(key, "")) for key in writer.fieldnames})
    audit_log("admin.export", request=request, actor_user_id=owner.get("google_id"), target_type="waitlist")
    return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=safescan-waitlist.csv"})

@qr_app.post("/admin/scans/{scan_id}/flag", dependencies=[Depends(require_csrf_form)])
async def admin_flag_scan(request: Request, scan_id: str):
    admin_user = require_role_user(request, "admin")
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        assert_owns_row(conn, "scan_history", scan_id)
        scan = conn.execute("SELECT * FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
        if not scan:
            raise HTTPException(status_code=404, detail="Not found.")
        if not str(scan["url"] or "").lower().startswith(("https://", "http://")):
            raise HTTPException(status_code=400, detail="Only web URL scans can be added to the URL blocklist.")
        conn.execute("UPDATE scan_history SET verdict = 'MALICIOUS', risk_score = 100 WHERE id = ?", (scan_id,))
        conn.execute("INSERT OR IGNORE INTO url_blocklist VALUES (?, ?, ?, ?, ?, NULL)", (make_id("block"), scan["url"], "Admin confirmed malicious scan", admin_user.get("email"), now_iso()))
    audit_log("admin.url_flagged", request=request, actor_user_id=admin_user.get("google_id"), target_type="scan", target_id=scan_id)
    return RedirectResponse("/admin/scans", status_code=303)

@qr_app.get("/admin/reports", response_class=HTMLResponse)
async def admin_reports(request: Request, tab: str = Query("reports")):
    return admin_context(request, "Reported URLs", "reports", lambda: fetch_reports(tab=tab))

@qr_app.post("/admin/reports/{report_id}/action", dependencies=[Depends(require_csrf_form)])
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

@qr_app.post("/admin/blocklist/{block_id}/remove", dependencies=[Depends(require_csrf_form)])
async def admin_remove_block(request: Request, block_id: str):
    admin_user = require_role_user(request, "admin")
    with get_conn() as conn:
        assert_owns_row(conn, "url_blocklist", block_id)
        conn.execute("UPDATE url_blocklist SET removed_at = ? WHERE id = ?", (now_iso(), block_id))
    audit_log("admin.blocklist_removed", request=request, actor_user_id=admin_user.get("google_id"), target_type="blocklist", target_id=block_id)
    return RedirectResponse("/admin/reports?tab=blocklist", status_code=303)

@qr_app.get("/admin/risk-logs", response_class=HTMLResponse)
async def admin_risk_logs(request: Request):
    return admin_context(request, "Risk Engine Logs", "scans", lambda: fetch_scans(verdict="MALICIOUS"))

@qr_app.get("/admin/airdrop", response_class=HTMLResponse)
async def admin_airdrop(request: Request):
    return admin_context(request, "Tier Overview", "airdrop", fetch_airdrop_data)

@qr_app.post("/admin/airdrop/distribute", response_class=HTMLResponse, dependencies=[Depends(require_csrf_form)])
async def admin_airdrop_distribute(request: Request):
    admin_user = require_role_user(request, "admin")
    require_same_origin_action(request)
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
    return admin_context(request, "Fraud Flags", "fraud", fetch_fraud_data)

@qr_app.get("/admin/airdrop/wallets", response_class=HTMLResponse)
async def admin_airdrop_wallets(request: Request):
    return admin_context(request, "Wallet Registry", "airdrop", fetch_airdrop_data)

@qr_app.post("/admin/airdrop/{email}/status", dependencies=[Depends(require_csrf_form)])
async def admin_airdrop_status(request: Request, email: str, status: str = Form(...), reason: str = Form("")):
    admin_user = require_role_user(request, "admin")
    if status not in ("eligible", "flagged", "disqualified", "cleared"):
        raise HTTPException(status_code=400, detail="Invalid request.")
    with get_conn() as conn:
        conn.execute("UPDATE users SET airdrop_status = ? WHERE email = ?", (status, email))
    audit_log("admin.airdrop_status_changed", request=request, actor_user_id=admin_user.get("google_id"), target_type="user", target_id=email, metadata={"status": status, "reason": reason})
    return RedirectResponse("/admin/airdrop", status_code=303)

@qr_app.post("/admin/fraud/{email}/review", dependencies=[Depends(require_csrf_form)])
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
    if export == "csv":
        owner = require_role_user(request, "owner")
        data = fetch_audit_logs(search=search, action=action, target_type=target_type)
        out = io.StringIO()
        writer = csv.DictWriter(out, fieldnames=["created_at", "actor_user_id", "action", "target_type", "target_id", "ip_address", "user_agent", "metadata"])
        writer.writeheader()
        for row in data["rows"]:
            writer.writerow({key: _safe_csv_cell(row.get(key, "")) for key in writer.fieldnames})
        audit_log("admin.export", request=request, actor_user_id=owner.get("google_id"), target_type="audit_logs")
        return Response(out.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=safescan-audit-logs.csv"})
    return admin_context(request, "Audit Logs", "logs", lambda: fetch_audit_logs(search=search, action=action, target_type=target_type))

@qr_app.get("/admin/api-keys", response_class=HTMLResponse)
async def admin_api_keys(request: Request):
    def load_data():
        with get_conn() as conn:
            conn.row_factory = sqlite3.Row
            keys = [dict(row) for row in conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC")]
        return {"keys": keys}

    return admin_context(request, "API Keys", "api_keys", load_data, owner_only=True)

@qr_app.post("/admin/api-keys", dependencies=[Depends(require_csrf_form)])
async def admin_create_api_key(request: Request, name: str = Form(...), scopes: list[str] = Form([]), expires_at: str = Form("")):
    owner = require_role_user(request, "owner")
    raw_key = "sk_live_" + secrets.token_urlsafe(32)
    hint = raw_key[:14] + "..."
    with get_conn() as conn:
        conn.execute("INSERT INTO api_keys VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, NULL, NULL)", (make_id("key"), name[:80], hint, hashlib.sha256(raw_key.encode()).hexdigest(), json.dumps(scopes), owner.get("email"), now_iso(), expires_at or None))
    audit_log("api_key.created", request=request, actor_user_id=owner.get("google_id"), target_type="api_key", metadata={"name": name, "scopes": scopes})
    return admin_context(request, "API Keys", "api_key_created", {"raw_key": raw_key}, owner_only=True)

@qr_app.post("/admin/api-keys/{key_id}/revoke", dependencies=[Depends(require_csrf_form)])
async def admin_revoke_api_key(request: Request, key_id: str):
    owner = require_role_user(request, "owner")
    with get_conn() as conn:
        assert_owns_row(conn, "api_keys", key_id)
        conn.execute("UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = ?", (now_iso(), key_id))
    audit_log("api_key.revoked", request=request, actor_user_id=owner.get("google_id"), target_type="api_key", target_id=key_id)
    return RedirectResponse("/admin/api-keys", status_code=303)

@qr_app.get("/admin/settings", response_class=HTMLResponse)
async def admin_settings(request: Request):
    def load_data():
        with get_conn() as conn:
            privileged = conn.execute(
                "SELECT email, role FROM users WHERE status = 'active' AND role IN ('admin', 'owner') ORDER BY role, email"
            ).fetchall()
        return {
            "app_url": APP_URL,
            "admin_emails": [row["email"] for row in privileged if row["role"] == "admin"],
            "owner_emails": [row["email"] for row in privileged if row["role"] == "owner"],
        }

    return admin_context(request, "Settings", "settings", load_data, owner_only=True)

