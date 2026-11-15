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
from .auth import get_session_user
from .auth import has_role
from .config import ADMIN_EMAIL
from .config import AIRDROP_BASE_ALLOCATION
from .config import AIRDROP_TOKEN_ALLOCATIONS
from .config import templates
from .history import admin_avatar
from .history import safe_scan_history_record
from .payload_privacy import safe_legacy_scan_value

# =============================================================================
# ADMIN CONSOLE — data-access helpers (the admin routes follow further below)
# =============================================================================
def safe_fraud_flag_record(row):
    result = dict(row)
    try:
        metadata = json.loads(result.get("metadata") or "{}")
    except (TypeError, ValueError):
        return result
    if isinstance(metadata, dict) and isinstance(metadata.get("url"), str):
        metadata["url"] = safe_legacy_scan_value(metadata["url"])
        result["metadata"] = json.dumps(metadata)
    return result


def admin_context(request, title, page, data=None, owner_only=False, status_code=200):
    admin_user = get_session_user(request)
    if not admin_user or not has_role(admin_user, "admin"):
        return RedirectResponse("/", status_code=303)
    if owner_only and not has_role(admin_user, "owner"):
        return RedirectResponse("/", status_code=303)
    context = {
        "request": request,
        "title": title,
        "page": page,
        "data": data or {},
        "admin_user": admin_user,
        "is_owner": has_role(admin_user, "owner"),
        "avatar": admin_avatar(admin_user.get("email")),
    }
    return templates.TemplateResponse("admin_shell.html", context, status_code=status_code)

def fetch_admin_users(search="", status="", role="", tier="", page=1, limit=25, flag=""):
    """Filter and paginate account rows after resolving their record ownership.

    Email-keyed legacy data is attributed only when one account owns that
    canonical email. Stable account-ID records remain visible for their owner.
    The database performs the filtering/counting so a later page cannot make
    the current page appear empty and Python holds only one page of rows.
    """
    clauses = []
    params = []
    if search:
        clauses.append("(e.email LIKE ? OR e.google_id LIKE ? OR COALESCE(e.display_name, '') LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if status:
        clauses.append("e.status = ?")
        params.append(status)
    if role:
        clauses.append("e.role = ?")
        params.append(role)
    if tier:
        clauses.append("lower(e.tier) = lower(?)")
        params.append(tier)
    if flag == "review":
        clauses.append("e.fraud_flags > 0")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    page = max(1, int(page))
    limit = max(1, min(int(limit), 10000))
    source = """
        WITH email_owners AS (
            SELECT canonical_email_key(email) AS email_key, COUNT(*) AS owner_count
            FROM users
            WHERE email IS NOT NULL
            GROUP BY canonical_email_key(email)
        ), scans_by_id AS (
            SELECT user_id, SUM(COALESCE(scan_count, 0)) AS scan_count,
                   MAX(wallet_address) AS wallet_address,
                   SUM(COALESCE(tokens_sent, 0)) AS tokens_sent,
                   SUM(COALESCE(airdrop_tokens_sent, 0)) AS airdrop_tokens_sent,
                   MAX(airdrop_sent_at) AS airdrop_sent_at
            FROM scans WHERE user_id IS NOT NULL AND user_id != '' GROUP BY user_id
        ), legacy_scans AS (
            SELECT canonical_email_key(email) AS email_key, SUM(COALESCE(scan_count, 0)) AS scan_count,
                   MAX(wallet_address) AS wallet_address,
                   SUM(COALESCE(tokens_sent, 0)) AS tokens_sent,
                   SUM(COALESCE(airdrop_tokens_sent, 0)) AS airdrop_tokens_sent,
                   MAX(airdrop_sent_at) AS airdrop_sent_at
            FROM scans WHERE user_id IS NULL OR user_id = '' GROUP BY canonical_email_key(email)
        ), referral_counts AS (
            SELECT canonical_email_key(referrer_email) AS email_key, COUNT(*) AS referral_count
            FROM referrals WHERE counted = 1 GROUP BY canonical_email_key(referrer_email)
        ), fraud_counts AS (
            SELECT user_id, COUNT(*) AS fraud_flags
            FROM fraud_flags WHERE reviewed = 0 GROUP BY user_id
        ), legacy_fraud_counts AS (
            SELECT canonical_email_key(f.user_id) AS email_key, COUNT(*) AS fraud_flags
            FROM fraud_flags f
            WHERE f.reviewed = 0
              AND NOT EXISTS (SELECT 1 FROM users owner WHERE owner.google_id = f.user_id)
            GROUP BY canonical_email_key(f.user_id)
        ), owned_users AS (
            SELECT u.*, canonical_email_key(u.email) AS email_key,
                   CASE WHEN o.email_key IS NOT NULL AND o.owner_count = 1 THEN 1 ELSE 0 END AS unique_email,
                   CASE WHEN o.email_key IS NULL OR o.owner_count != 1 THEN 1 ELSE 0 END AS ambiguous_email
            FROM users u
            LEFT JOIN email_owners o ON o.email_key = canonical_email_key(u.email)
        ), account_data AS (
            SELECT u.*,
                   COALESCE(s.scan_count, 0) + COALESCE(legacy_s.scan_count, 0) AS scan_count,
                   COALESCE(w.address, legacy_w.address, s.wallet_address, legacy_s.wallet_address) AS wallet_address,
                   COALESCE(w.verified, legacy_w.verified) AS wallet_verified,
                   COALESCE(w.sol_balance, legacy_w.sol_balance) AS sol_balance,
                   COALESCE(w.tx_count, legacy_w.tx_count) AS tx_count,
                   COALESCE(w.wallet_age_days, legacy_w.wallet_age_days) AS wallet_age_days,
                   COALESCE(w.onchain_verified_at, legacy_w.onchain_verified_at) AS onchain_verified_at,
                   COALESCE(s.tokens_sent, 0) + COALESCE(legacy_s.tokens_sent, 0) AS tokens_sent,
                   COALESCE(s.airdrop_tokens_sent, 0) + COALESCE(legacy_s.airdrop_tokens_sent, 0) AS airdrop_tokens_sent,
                   COALESCE(s.airdrop_sent_at, legacy_s.airdrop_sent_at) AS airdrop_sent_at,
                   CASE WHEN u.unique_email = 1 THEN COALESCE(r.referral_count, 0) ELSE 0 END AS referral_count,
                   COALESCE(f_id.fraud_flags, 0) +
                       CASE WHEN u.unique_email = 1
                            THEN COALESCE(f_legacy.fraud_flags, 0) ELSE 0 END AS fraud_flags
            FROM owned_users u
            LEFT JOIN scans_by_id s ON u.unique_email = 1 AND s.user_id = u.google_id
            LEFT JOIN legacy_scans legacy_s ON u.unique_email = 1 AND legacy_s.email_key = u.email_key
            LEFT JOIN referral_counts r ON u.unique_email = 1 AND r.email_key = u.email_key
            LEFT JOIN fraud_counts f_id ON f_id.user_id = u.google_id
            LEFT JOIN legacy_fraud_counts f_legacy ON u.unique_email = 1 AND f_legacy.email_key = u.email_key
            LEFT JOIN wallets w ON w.user_id = u.google_id AND w.verified = 1
            LEFT JOIN wallets legacy_w ON u.unique_email = 1 AND legacy_w.user_id = u.email
                AND legacy_w.verified = 1 AND w.user_id IS NULL
        ), enriched AS (
            SELECT account_data.*,
                   CASE
                       WHEN ambiguous_email = 1 THEN 'Ownership review'
                       WHEN scan_count >= 50 AND referral_count >= 2 THEN 'Guardian'
                       WHEN scan_count >= 5 AND referral_count >= 1 THEN 'Referrer'
                       WHEN scan_count >= 5 THEN 'Scanner'
                       ELSE 'Registered'
                   END AS tier
            FROM account_data
        )
    """
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.create_function("canonical_email_key", 1, canonical_email_key, deterministic=True)
        total = conn.execute(f"{source} SELECT COUNT(*) FROM enriched e {where}", params).fetchone()[0]
        pages = max(1, (total + limit - 1) // limit)
        page = min(page, pages)
        offset = (page - 1) * limit
        rows = [dict(row) for row in conn.execute(
            f"{source} SELECT * FROM enriched e {where} "
            "ORDER BY COALESCE(e.last_login_at, e.last_login, e.created_at) DESC, e.google_id "
            "LIMIT ? OFFSET ?",
            params + [limit, offset]
        )]
    return {"rows": rows, "total": total, "page": page, "limit": limit, "pages": pages}

def fetch_user_detail(reference):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.create_function("canonical_email_key", 1, canonical_email_key, deterministic=True)
        user_row = conn.execute("SELECT * FROM users WHERE google_id = ?", (reference,)).fetchone()
        if user_row is None:
            # The old drawer URL contains an email. Keep it only when that
            # address identifies exactly one account, including IDNA aliases.
            key = canonical_email_key(reference)
            matches = [row for row in conn.execute("SELECT * FROM users WHERE email IS NOT NULL")
                       if canonical_email_key(row["email"]) == key] if key else []
            user_row = matches[0] if len(matches) == 1 else None
        if user_row is None:
            return {"user": None, "flags": [], "logs": [], "scans": []}
        user = dict(user_row)
        user_id = user["google_id"]
        email = user.get("email") or ""
        legacy_owner = unique_email_owner(conn, email, user_id)
        legacy_enabled = int(legacy_owner)
        email_key = canonical_email_key(email)

        # Current records are keyed by account ID. Email-only records are
        # attributable only when there is a single canonical email owner.
        scan_params = (user_id, legacy_enabled, email_key, email_key)
        user["scan_count"] = conn.execute(
            "SELECT COUNT(*) FROM scan_history WHERE user_id = ? "
            "OR (? = 1 AND (user_id IS NULL OR user_id = '' OR "
            "(canonical_email_key(user_id) = ? AND user_id NOT IN (SELECT google_id FROM users))) "
            "AND canonical_email_key(email) = ?)",
            scan_params,
        ).fetchone()[0] if legacy_owner else 0
        user["ownership_ambiguous"] = not legacy_owner
        user["scan_history_withheld"] = not legacy_owner
        wallet = conn.execute(
            "SELECT * FROM wallets WHERE user_id = ? AND verified = 1", (user_id,),
        ).fetchone()
        if wallet is None and legacy_owner:
            legacy_wallets = conn.execute(
                "SELECT * FROM wallets WHERE canonical_email_key(user_id) = ? AND verified = 1 "
                "AND user_id NOT IN (SELECT google_id FROM users)", (email_key,),
            ).fetchall()
            wallet = legacy_wallets[0] if len(legacy_wallets) == 1 else None
        for field in ("wallet_verified", "wallet_address", "sol_balance", "tx_count",
                      "wallet_age_days", "onchain_verified_at"):
            user[field] = None
        if wallet is not None:
            user.update({
                "wallet_verified": wallet["verified"],
                "wallet_address": wallet["address"],
                "sol_balance": wallet["sol_balance"],
                "tx_count": wallet["tx_count"],
                "wallet_age_days": wallet["wallet_age_days"],
                "onchain_verified_at": wallet["onchain_verified_at"],
            })
        flags = [safe_fraud_flag_record(row) for row in conn.execute(
            "SELECT * FROM fraud_flags WHERE user_id = ? OR (? = 1 AND canonical_email_key(user_id) = ? "
            "AND user_id NOT IN (SELECT google_id FROM users)) "
            "ORDER BY created_at DESC LIMIT 50", (user_id, legacy_enabled, email_key),
        )]
        logs = [dict(row) for row in conn.execute(
            "SELECT * FROM audit_logs WHERE actor_user_id = ? "
            "OR (target_type = 'user' AND target_id = ?) "
            "OR (? = 1 AND ((canonical_email_key(actor_user_id) = ? "
            "AND actor_user_id NOT IN (SELECT google_id FROM users)) "
            "OR (target_type = 'user' AND canonical_email_key(target_id) = ? "
            "AND target_id NOT IN (SELECT google_id FROM users)))) "
            "ORDER BY created_at DESC LIMIT 50",
            (user_id, user_id, legacy_enabled, email_key, email_key),
        )]
        scans = [safe_scan_history_record(row) for row in conn.execute(
            "SELECT * FROM scan_history WHERE user_id = ? "
            "OR (? = 1 AND (user_id IS NULL OR user_id = '' OR "
            "(canonical_email_key(user_id) = ? AND user_id NOT IN (SELECT google_id FROM users))) "
            "AND canonical_email_key(email) = ?) ORDER BY created_at DESC LIMIT 50",
            scan_params,
        )] if legacy_owner else []
    return {"user": user, "flags": flags, "logs": logs, "scans": scans}

def dashboard_data():
    today = datetime.utcnow().date().isoformat()
    since_30 = (datetime.utcnow() - timedelta(days=30)).isoformat()
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        total_users = conn.execute("SELECT COUNT(*) FROM users WHERE status != 'deleted'").fetchone()[0]
        scans_today = conn.execute("SELECT COUNT(*) FROM scan_history WHERE created_at >= ?", (today,)).fetchone()[0]
        blocked = conn.execute("SELECT COUNT(*) FROM scan_history WHERE verdict IN ('MALICIOUS', 'HIGH') OR risk_score >= 80").fetchone()[0]
        fraud_flags = conn.execute("SELECT COUNT(*) FROM fraud_flags WHERE reviewed = 0").fetchone()[0]
        recent_users = [dict(row) for row in conn.execute("SELECT u.*, COALESCE(w.address, s.wallet_address) AS wallet_address, COALESCE(s.scan_count, 0) AS scan_count FROM users u LEFT JOIN scans s ON s.email = u.email LEFT JOIN wallets w ON w.user_id = u.email AND w.verified = 1 ORDER BY COALESCE(u.created_at, u.last_login) DESC LIMIT 10")]
        for user in recent_users:
            owned_email = unique_email_owner(conn, user.get("email"), user["google_id"])
            own_wallet = conn.execute(
                "SELECT address FROM wallets WHERE user_id = ? AND verified = 1",
                (user["google_id"],),
            ).fetchone()
            if own_wallet is not None:
                user["wallet_address"] = own_wallet["address"]
            elif not owned_email:
                user["wallet_address"] = None
            if not owned_email:
                user["scan_count"] = 0
        recent_reports = [dict(row) for row in conn.execute("SELECT * FROM url_reports ORDER BY created_at DESC LIMIT 10")]
        activity = [dict(row) for row in conn.execute(
            """
            SELECT a.*,
                   COALESCE(actor_by_id.email, actor_by_email.email) AS actor_email
            FROM audit_logs a
            LEFT JOIN users actor_by_id ON actor_by_id.google_id = a.actor_user_id
            LEFT JOIN users actor_by_email ON lower(actor_by_email.email) = lower(a.actor_user_id)
            ORDER BY a.created_at DESC
            LIMIT 20
            """
        )]
        chart_rows = [dict(row) for row in conn.execute(
            "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total, SUM(CASE WHEN risk_score >= 80 THEN 1 ELSE 0 END) AS flagged FROM scan_history WHERE created_at >= ? GROUP BY day ORDER BY day",
            (since_30,)
        )]
        verdict_rows = [dict(row) for row in conn.execute("SELECT COALESCE(verdict, 'SAFE') AS verdict, COUNT(*) AS count FROM scan_history GROUP BY verdict")]
    return {
        "stats": [
            {"label": "Total Users", "value": total_users, "trend": "+0%", "icon": "users"},
            {"label": "QR Scans Today", "value": scans_today, "trend": "+0%", "icon": "scan"},
            {"label": "Malicious Blocked", "value": blocked, "trend": "+0%", "icon": "shield"},
            {"label": "Active Fraud Flags", "value": fraud_flags, "trend": "+0%", "icon": "flag", "danger": fraud_flags > 0},
        ],
        "recent_users": recent_users,
        "recent_reports": recent_reports,
        "activity": activity,
        "chart_rows": chart_rows,
        "verdict_rows": verdict_rows,
    }

def fetch_scans(search="", verdict="", user="", limit=100):
    clauses = []
    params = []
    if search:
        clauses.append("url LIKE ?")
        params.append(f"%{search}%")
    if verdict:
        clauses.append("verdict = ?")
        params.append(verdict)
    if user:
        clauses.append("email LIKE ?")
        params.append(f"%{user}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = [safe_scan_history_record(row) for row in conn.execute(f"SELECT * FROM scan_history {where} ORDER BY created_at DESC LIMIT ?", params + [limit])]
        total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
        flagged_today = conn.execute("SELECT COUNT(*) FROM scan_history WHERE risk_score >= 80 AND created_at >= ?", (datetime.utcnow().date().isoformat(),)).fetchone()[0]
        avg_risk = conn.execute("SELECT AVG(risk_score) FROM scan_history WHERE created_at >= ?", ((datetime.utcnow() - timedelta(days=7)).isoformat(),)).fetchone()[0] or 0
    return {"rows": rows, "stats": {"total": total, "flagged_today": flagged_today, "avg_risk": round(avg_risk, 1), "common_tld": "n/a"}}

def fetch_reports(tab="reports"):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        reports = [dict(row) for row in conn.execute("SELECT * FROM url_reports ORDER BY created_at DESC LIMIT 200")]
        blocklist = [dict(row) for row in conn.execute("SELECT * FROM url_blocklist WHERE removed_at IS NULL ORDER BY created_at DESC LIMIT 200")]
    for row in blocklist:
        row["url"] = safe_legacy_scan_value(row.get("url"))
    return {"reports": reports, "blocklist": blocklist, "tab": tab}

def fetch_waitlist(search="", limit=500):
    bounded_limit = max(1, min(int(limit or 500), 5000))
    normalized_search = (search or "").strip().lower()
    candidates = [database_path(), "/app/data/qr_cache.db", "/var/data/qr_cache.db"]
    seen_paths = []
    signups = {}
    total = 0
    for candidate in candidates:
        if not candidate or candidate in seen_paths or not os.path.exists(candidate):
            continue
        seen_paths.append(candidate)
        try:
            with sqlite3.connect(candidate) as conn:
                conn.row_factory = sqlite3.Row
                table = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'waitlist_signups'"
                ).fetchone()
                if not table:
                    continue
                conn.create_function(
                    "waitlist_email_key", 1,
                    lambda value: (value or "").strip().lower(), deterministic=True,
                )
                rows = conn.execute(
                    "SELECT email, source, created_at FROM waitlist_signups "
                    "WHERE email IS NOT NULL AND instr(waitlist_email_key(email), ?) > 0 "
                    "ORDER BY created_at DESC LIMIT ?",
                    (normalized_search, bounded_limit),
                ).fetchall()
        except sqlite3.Error:
            continue
        for row in rows:
            email = (row["email"] or "").strip().lower()
            if not email or (normalized_search and normalized_search not in email):
                continue
            existing = signups.get(email)
            current = dict(row)
            if not existing or str(current.get("created_at") or "") > str(existing.get("created_at") or ""):
                signups[email] = current
    rows = sorted(signups.values(), key=lambda row: row.get("created_at") or "", reverse=True)[:bounded_limit]
    total = len(signups)
    return {"rows": rows, "total": total, "filters": {"search": search}, "limit": bounded_limit}

def fetch_airdrop_data():
    users = fetch_admin_users(limit=10000)["rows"]
    wallet_users = [row for row in users if row.get("wallet_address")]
    tier_counts = {"Registered": 0, "Scanner": 0, "Referrer": 0, "Guardian": 0}
    for row in wallet_users:
        tier_counts[row["tier"]] = tier_counts.get(row["tier"], 0) + 1
        row["estimated_sqr"] = AIRDROP_TOKEN_ALLOCATIONS.get(row["tier"], 0)
        row["distribution_status"] = "ownership review" if row.get("ambiguous_email") else ("sent" if row.get("tokens_sent") else ("blocked" if row.get("airdrop_status") in ("flagged", "disqualified") or row.get("fraud_flags") else ("qualified" if row["estimated_sqr"] > 0 else "pending")))
    flagged = [row for row in users if row.get("airdrop_status") == "flagged" or row.get("fraud_flags")]
    qualified = [
        row for row in wallet_users
        if row.get("distribution_status") == "qualified"
        and not row.get("ambiguous_email")
        and row.get("status") == "active"
        and row.get("airdrop_status") in ("eligible", "cleared")
    ]
    distributed_total = sum(int(row.get("airdrop_tokens_sent") or 0) for row in wallet_users)
    return {
        "wallet_users": wallet_users,
        "qualified": qualified,
        "tier_counts": tier_counts,
        "flagged": flagged,
        "estimated_total": sum(row.get("estimated_sqr", 0) for row in qualified),
        "distributed_total": distributed_total,
        "base_allocation": AIRDROP_BASE_ALLOCATION,
    }

def airdrop_tier(scan_count, referrals):
    """Map a user's scan/referral counts to a reward tier name.

    NOTE: kept in sync with ``distribute.airdrop_tier`` (the airdrop job uses its
    own copy to avoid importing the heavy Solana stack into the web app). If you
    change the thresholds here, change them there too.
    """
    if scan_count >= 50 and referrals >= 2:
        return "Guardian"
    if scan_count >= 5 and referrals >= 1:
        return "Referrer"
    if scan_count >= 5:
        return "Scanner"
    return "Pending"

def next_airdrop_milestone(scan_count, referrals):
    """Human-readable hint telling the user what to do to reach the next tier."""
    if scan_count < 5:
        return f"Scan {5 - scan_count} more QR code{'s' if 5 - scan_count != 1 else ''} to unlock Scanner."
    if referrals < 1:
        return "Invite 1 user with your referral link to unlock Referrer."
    if scan_count < 50 or referrals < 2:
        return "Scan 50 QR codes and invite multiple people to unlock Guardian."
    return "Guardian tier unlocked."

def fetch_fraud_data():
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        users = {row["google_id"]: dict(row) for row in conn.execute("SELECT * FROM users")}
        owners_by_email = {}
        for user in users.values():
            key = canonical_email_key(user.get("email"))
            if key:
                owners_by_email.setdefault(key, []).append(user["google_id"])
        flags_by_user = {}
        unassigned_flags = {}
        for flag in conn.execute("SELECT user_id, severity, created_at FROM fraud_flags WHERE reviewed = 0"):
            flag_owner = flag["user_id"]
            if flag_owner not in users:
                key = canonical_email_key(flag_owner)
                owners = owners_by_email.get(key, []) if key else []
                flag_owner = owners[0] if len(owners) == 1 else None
            if flag_owner is None:
                unassigned_flags.setdefault(flag["user_id"], []).append(flag)
            else:
                flags_by_user.setdefault(flag_owner, []).append(flag)

        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        rows = []
        for account_id, flags in flags_by_user.items():
            user = users[account_id]
            email = user.get("email") or ""
            email_owned = owners_by_email.get(canonical_email_key(email)) == [account_id]
            wallet = conn.execute(
                "SELECT address FROM wallets WHERE user_id = ? AND verified = 1", (account_id,),
            ).fetchone()
            if wallet is None and email_owned:
                wallet = conn.execute(
                    "SELECT address FROM wallets WHERE user_id = ? AND verified = 1", (email,),
                ).fetchone()
            scan = conn.execute(
                "SELECT user_id, scan_count, wallet_address FROM scans WHERE lower(email) = lower(?)", (email,),
            ).fetchone()
            scan_owned = email_owned and scan is not None and (scan["user_id"] == account_id or (
                email_owned and not scan["user_id"]
            ))
            rows.append({
                "google_id": account_id,
                "email": email,
                "role": user.get("role"),
                "airdrop_status": user.get("airdrop_status"),
                "fraud_score": user.get("fraud_score") or 0,
                "wallet_address": wallet["address"] if wallet else (scan["wallet_address"] if scan_owned else None),
                "scan_count": scan["scan_count"] if scan_owned else 0,
                "signal_count": len(flags),
                "highest_severity": max((flag["severity"] for flag in flags), key=lambda value: severity_rank.get(value, 0)),
                "flag_date": max(flag["created_at"] for flag in flags),
                "ambiguous_email": int(not email_owned),
            })
        # Email-only flags for shared or unknown addresses stay visible as
        # unassigned records, never as claims on either account.
        for email, flags in unassigned_flags.items():
            rows.append({
                "google_id": None, "email": email, "role": None,
                "airdrop_status": "Unassigned", "fraud_score": 0,
                "wallet_address": None, "scan_count": 0,
                "signal_count": len(flags),
                "highest_severity": max((flag["severity"] for flag in flags), key=lambda value: severity_rank.get(value, 0)),
                "flag_date": max(flag["created_at"] for flag in flags),
                "ambiguous_email": 1,
            })
        rows.sort(key=lambda row: (row["fraud_score"], row["flag_date"]), reverse=True)
    return {"rows": rows}

def fetch_audit_logs(search="", action="", target_type=""):
    clauses = []
    params = []
    if search:
        clauses.append("(a.actor_user_id LIKE ? OR actor_by_id.email LIKE ? OR actor_by_email.email LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if action:
        clauses.append("action = ?")
        params.append(action)
    if target_type:
        clauses.append("target_type = ?")
        params.append(target_type)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = [dict(row) for row in conn.execute(
            f"""
            SELECT a.*,
                   COALESCE(actor_by_id.email, actor_by_email.email) AS actor_email
            FROM audit_logs a
            LEFT JOIN users actor_by_id ON actor_by_id.google_id = a.actor_user_id
            LEFT JOIN users actor_by_email ON lower(actor_by_email.email) = lower(a.actor_user_id)
            {where}
            ORDER BY a.created_at DESC
            LIMIT 300
            """,
            params,
        )]
        actions = [row[0] for row in conn.execute("SELECT DISTINCT action FROM audit_logs ORDER BY action")]
    return {"rows": rows, "actions": actions}

PRIVACY_POLICY_HTML = f"""
<h2>1. What We Collect</h2>
<p>SafeScan QR collects only what is needed to authenticate users, analyze QR payloads, prevent abuse, and operate the optional SQR airdrop program.</p>
<ul>
  <li>Google OAuth data: name, email, profile picture, Google ID, and login timestamp.</li>
  <li>Optional Solana wallet address supplied by the user for airdrop eligibility.</li>
  <li>QR scan payloads such as URLs analyzed for risk. Logged-in scans may be associated with the user's email for scan counts and fraud prevention.</li>
  <li>Referral link usage and referral counts.</li>
  <li>IP address hash, approximate region, browser type, device type, and session signals for fraud prevention and analytics.</li>
  <li>Cookies and local storage values for authentication state, consent state, referral state, wallet state, and local report queues.</li>
</ul>
<p>Live camera preview frames are checked in your browser. If the local reader fails, SafeScan sends a captured photo to its server only after you choose “Send photo to SafeScan.” The server processes that photo in memory to read the QR code and does not store the image. The decoded payload follows the scan-history rules described here; signed-in scans may be saved.</p>
<p>If you accept optional analytics, the upgraded scanner sends aggregate performance counts, such as decoder type, elapsed time, outcome, and guidance category. These counts do not include QR text, photos, or device identifiers.</p>
<h2>2. Why We Collect It and Legal Basis</h2>
<ul>
  <li>Authentication: contractual necessity.</li>
  <li>Scan history and QR security delivery: legitimate interest in providing and improving security analysis.</li>
  <li>Airdrop eligibility, scan tiers, referrals, and wallet address: contractual necessity for the tier program.</li>
  <li>Analytics and abuse prevention: legitimate interest.</li>
  <li>Marketing emails: explicit consent only.</li>
</ul>
<h2>3. How Long We Keep It</h2>
<ul>
  <li>Signed-in user scan history and leaderboard counters: retained as long-term account records unless deletion is requested or the account is removed.</li>
  <li>Account data: until deletion is requested or after 2 years of inactivity.</li>
  <li>Wallet address: until the user disconnects it or deletes the account.</li>
  <li>Consent records: retained for 5 years to document legal compliance.</li>
</ul>
<h2>4. Who We Share It With</h2>
<p>We do not sell personal data and do not use advertising networks. We may share limited data with service providers only as needed:</p>
<ul>
  <li>Google for OAuth authentication and, when configured, Google Web Risk checks of web URLs.</li>
  <li>PhishTank supplies a phishing feed that SafeScan checks locally; individual scanned URLs are not sent to PhishTank.</li>
  <li>Anthropic or OpenAI for AI analysis. URL payloads and risk signals may be sent, but direct personal identifiers are excluded.</li>
  <li>Solana RPC providers for wallet interactions involving public blockchain data.</li>
  <li>Render.com for hosting infrastructure.</li>
</ul>
<h2>5. Cookies and Tracking</h2>
<p>SafeScan uses essential cookies/local storage for auth, consent, referral, wallet, and report state. Analytics is optional and should only run after consent where required.</p>
<h2>6. Your Rights</h2>
<p>EU/EEA users may exercise GDPR rights of access, erasure, rectification, restriction, portability, and objection. California users may exercise CCPA/CPRA rights to know, delete, correct, opt out of sale/sharing, limit sensitive personal information, and non-discrimination. Brazilian users may exercise LGPD rights including revoking consent and requesting information about public and private entities with whom data is shared. Canadian users are protected under PIPEDA principles: knowledge and consent, limited use, accuracy, safeguards, access, and the right to challenge compliance.</p>
<p>Use the <a href="/legal/data-request">Data Request portal</a> to submit requests.</p>
<h2>7. Children's Privacy</h2>
<p>SafeScan is not directed to children under 13. EU users under 16 require parental consent under GDPR Article 8. If we discover an underage user, we will delete associated data promptly.</p>
<h2>8. International Data Transfers</h2>
<p>Data is hosted in the United States. For EU users, transfers are intended to be covered by Standard Contractual Clauses or other appropriate safeguards where required.</p>
<h2>9. Security Measures</h2>
<ul>
  <li>TLS encryption in transit.</li>
  <li>Wallet addresses should be hashed or encrypted at rest as the product matures.</li>
  <li>OAuth tokens are not intentionally stored; SafeScan keeps only account/session references.</li>
  <li>Security incidents are tracked for GDPR Article 33 72-hour supervisory authority review and Article 34 user notice if high risk.</li>
</ul>
<h2>10. Contact</h2>
<p>Privacy requests: <a href="mailto:{ADMIN_EMAIL}">{ADMIN_EMAIL}</a>. A formal Data Protection Officer is not required at current scale but will be appointed upon reaching 5,000 EU users or when legally required.</p>
"""

TERMS_HTML = """
<h2>1. Acceptance of Terms</h2>
<p>By using SafeScan QR, you agree to these Terms. If you do not agree, do not use the service. You must be at least 13 globally, or 16 in the EU without parental consent.</p>
<h2>2. Description of Service</h2>
<p>SafeScan QR is an informational QR risk analysis tool. Risk verdicts are not guarantees of safety. The SQR airdrop program is discretionary, subject to change, and does not provide financial advice.</p>
<h2>3. User Accounts</h2>
<p>Google OAuth is used for authentication. You are responsible for account security. One account per person is allowed; multiple accounts for airdrop gaming may lead to disqualification. SafeScan may suspend accounts for abuse, fraud, bot activity, or security risk.</p>
<h2>4. Acceptable Use</h2>
<ul>
  <li>No automated bots to inflate scan counts or referrals.</li>
  <li>No intentional stress-testing or abuse of the risk engine.</li>
  <li>No reverse-engineering, scraping, or resale of scan results.</li>
  <li>No laundering, cloaking, or obscuring malicious URLs.</li>
  <li>No impersonating SafeScan in referral campaigns.</li>
</ul>
<h2>5. Airdrop Program Terms</h2>
<p>SQR has no guaranteed monetary value. Eligibility is tracked in SafeScan's database and may be checked against on-chain activity. SafeScan may disqualify fraudulent activity and may change timing or allocation at its sole discretion. Token receipt does not constitute investment advice or an offer of securities. The airdrop is unavailable where token distributions are prohibited or restricted, including jurisdictions where compliance cannot be satisfied.</p>
<h2>6. Intellectual Property</h2>
<p>The SafeScan name, UI, and product assets are proprietary. Users grant SafeScan a limited license to process submitted URLs and QR payloads for service delivery. SafeScan does not claim ownership of user scan data.</p>
<h2>7. Disclaimers and Limitation of Liability</h2>
<p>The service is provided as is, with no uptime guarantee at this stage. SafeScan is not liable for losses caused by acting on or ignoring a risk verdict. Liability is capped at $100 or the amount paid to SafeScan in the last 12 months, whichever is greater.</p>
<h2>8. Governing Law and Dispute Resolution</h2>
<p>These Terms are governed by Florida law. Disputes are resolved by binding arbitration under AAA rules, with a class action waiver. EU users retain the right to lodge complaints with their local supervisory authority.</p>
<h2>9. Changes to Terms</h2>
<p>SafeScan will provide 30 days notice before material changes where practical. Continued use means acceptance. Version history will be maintained at /legal/terms-history.</p>
"""

COOKIE_POLICY_HTML = """
<h2>Cookie Table</h2>
<table class="legal-table">
  <thead><tr><th>Cookie Name</th><th>Provider</th><th>Purpose</th><th>Type</th><th>Duration</th></tr></thead>
  <tbody>
    <tr><td>session token</td><td>SafeScan</td><td>Authentication session reference</td><td>Essential</td><td>Session</td></tr>
    <tr><td>consent-id</td><td>SafeScan</td><td>Stores consent record ID</td><td>Essential</td><td>12 months</td></tr>
    <tr><td>phishproofAirdropProfile</td><td>SafeScan local storage</td><td>Stores local demo profile and wallet state</td><td>Functional</td><td>Until cleared</td></tr>
    <tr><td>safeScanConsent</td><td>SafeScan local storage</td><td>Stores local consent choice so the banner does not reappear unnecessarily</td><td>Essential</td><td>12 months</td></tr>
    <tr><td>safeScanReports</td><td>SafeScan local storage</td><td>Stores local Block & Report queue</td><td>Functional</td><td>Until cleared</td></tr>
  </tbody>
</table>
<p>No third-party advertising cookies are used. If Google Analytics or similar analytics is added, it must be listed here before deployment and gated by consent where required.</p>
<h2>Disable Cookies</h2>
<p>You can manage cookies in <a href="https://support.google.com/chrome/answer/95647" target="_blank" rel="noopener noreferrer">Chrome</a>, <a href="https://support.mozilla.org/en-US/kb/clear-cookies-and-site-data-firefox" target="_blank" rel="noopener noreferrer">Firefox</a>, <a href="https://support.apple.com/guide/safari/manage-cookies-sfri11471/mac" target="_blank" rel="noopener noreferrer">Safari</a>, and <a href="https://support.microsoft.com/microsoft-edge" target="_blank" rel="noopener noreferrer">Edge</a>.</p>
"""

