from __future__ import annotations
import requests
import json
import warnings
import io
import sqlite3
import logging
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
    unique_email_owner,
)
from storage import backend_status as storage_backend_status
from storage import download_file as storage_download_file
from storage import object_key as storage_object_key
from storage import upload_bytes as storage_upload_bytes

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration
from .config import ADMIN_EMAIL
from .config import CLIENT_ID
from .config import LEGAL_LAST_UPDATED
from .config import LEGAL_VERSION

# =============================================================================
# LEGAL PAGES, LOCALE & GDPR DATA EXPORT/DELETE
# =============================================================================
def legal_context(request: Request, title, body_html):
    return {
        "request": request,
        "title": title,
        "body_html": body_html,
        "last_updated": LEGAL_LAST_UPDATED,
        "version": LEGAL_VERSION,
        "admin_email": ADMIN_EMAIL,
        "google_client_id": CLIENT_ID
    }


_GO_GHOST_STATUS_SQL = {
    "go_ghost_subjects": (
        "SELECT * FROM go_ghost_subjects WHERE user_id = ?",
        "DELETE FROM go_ghost_subjects WHERE user_id = ?",
    ),
    "go_ghost_consents": (
        "SELECT * FROM go_ghost_consents WHERE user_id = ?",
        "DELETE FROM go_ghost_consents WHERE user_id = ?",
    ),
    "go_ghost_requests": (
        "SELECT * FROM go_ghost_requests WHERE user_id = ?",
        "DELETE FROM go_ghost_requests WHERE user_id = ?",
    ),
}

# Tables with security, payment, suppression, or other people's records require
# an operator to decide what may be erased. This list is deliberately explicit:
# a new table must be reviewed before automatic account erasure is expanded.
_ERASURE_REVIEW_QUERIES = {
    "billing subscriptions": ("SELECT 1 FROM alpha_subscriptions WHERE user_id = ? LIMIT 1", "user"),
    "card checkout consents": ("SELECT 1 FROM stripe_checkout_intents WHERE user_id = ? LIMIT 1", "user"),
    "Solana payments": ("SELECT 1 FROM alpha_solana_payment_references WHERE user_id = ? LIMIT 1", "user"),
    "consent proofs": ("SELECT 1 FROM consent_logs WHERE user_id = ? LIMIT 1", "user"),
    "previous privacy requests": ("SELECT 1 FROM data_requests WHERE lower(email) = lower(?) LIMIT 1", "email"),
    "privacy suppressions": ("SELECT 1 FROM privacy_opt_outs WHERE lower(email) = lower(?) LIMIT 1", "email"),
    "email suppressions": ("SELECT 1 FROM email_suppressions WHERE lower(email) = lower(?) LIMIT 1", "email"),
    "security audit": ("SELECT 1 FROM audit_logs WHERE actor_user_id = ? LIMIT 1", "user"),
    "fraud evidence": ("SELECT 1 FROM fraud_flags WHERE user_id = ? LIMIT 1", "user"),
    "abuse evidence": ("SELECT 1 FROM abuse_flags WHERE lower(email) = lower(?) LIMIT 1", "email"),
    "IP registry": ("SELECT 1 FROM ip_registry WHERE user_id = ? LIMIT 1", "user"),
    "API keys": ("SELECT 1 FROM api_keys WHERE created_by = ? OR lower(created_by) = lower(?) LIMIT 1", "both"),
    "retained uploads": ("SELECT 1 FROM upload_artifacts WHERE user_id = ? OR lower(email) = lower(?) LIMIT 1", "both"),
    "URL reports": ("SELECT 1 FROM url_reports WHERE lower(reporter_email) = lower(?) LIMIT 1", "email"),
    "URL blocklist entries": ("SELECT 1 FROM url_blocklist WHERE added_by = ? OR lower(added_by) = lower(?) LIMIT 1", "both"),
    "referrals": ("SELECT 1 FROM referrals WHERE lower(referrer_email) = lower(?) OR lower(referred_email) = lower(?) LIMIT 1", "emails"),
}


def _erasure_review_reasons(conn, email, user_id):
    reasons = []
    if os.getenv("RETENTION_LEGAL_HOLD", "").strip().lower() in {"1", "true", "yes"}:
        reasons.append("documented legal hold")
    for label, (sql, scope) in _ERASURE_REVIEW_QUERIES.items():
        params = {"user": (user_id,), "email": (email,),
                  "both": (user_id, email), "emails": (email, email)}[scope]
        if conn.execute(sql, params).fetchone():
            reasons.append(label)
    return reasons


def _rows(conn, sql, params):
    return [dict(row) for row in conn.execute(sql, params)]


def _go_ghost_status_table_exists(conn, table):
    if table not in _GO_GHOST_STATUS_SQL:
        raise ValueError("Unknown Go Ghost status table")
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def _go_ghost_status_export(conn, table, user_id):
    if not _go_ghost_status_table_exists(conn, table):
        return []
    return [dict(row) for row in conn.execute(
        _GO_GHOST_STATUS_SQL[table][0], (user_id,)
    )]

def get_user_export(email, user_id):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")
        if not unique_email_owner(conn, email, user_id):
            count_queries = (
                "SELECT COUNT(*) FROM scans WHERE user_id = ? OR lower(email) = lower(?)",
                "SELECT COUNT(*) FROM scan_events WHERE user_id = ? OR lower(email) = lower(?)",
                "SELECT COUNT(*) FROM scan_history WHERE user_id = ? OR lower(email) = lower(?)",
            )
            count = sum(conn.execute(query, (user_id, email)).fetchone()[0] for query in count_queries)
            if count:
                logging.getLogger(__name__).warning(
                    "Withheld %d scan rows from ambiguous privacy export pending ownership review", count
                )
            return None
        scans = [dict(row) for row in conn.execute(
            "SELECT * FROM scans WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            (user_id, email),
        )]
        events = [dict(row) for row in conn.execute(
            "SELECT * FROM scan_events WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            (user_id, email),
        )]
        requests_ = [dict(row) for row in conn.execute("SELECT * FROM data_requests WHERE lower(email) = lower(?)", (email,))]
        age = [dict(row) for row in conn.execute("SELECT * FROM age_confirmations WHERE lower(email) = lower(?)", (email,))]
        age_eligibility = [dict(row) for row in conn.execute(
            "SELECT * FROM age_eligibility WHERE user_id = ?", (user_id,)
        )]
        opt_outs = [dict(row) for row in conn.execute("SELECT * FROM privacy_opt_outs WHERE lower(email) = lower(?)", (email,))]
        ghost_subjects = _go_ghost_status_export(conn, "go_ghost_subjects", user_id)
        ghost_consents = _go_ghost_status_export(conn, "go_ghost_consents", user_id)
        ghost_requests = _go_ghost_status_export(conn, "go_ghost_requests", user_id)
        ghost_legacy_jobs = [dict(row) for row in conn.execute(
            "SELECT * FROM go_ghost_removal_jobs WHERE user_id = ?", (user_id,)
        )]
        billing_consents = [dict(row) for row in conn.execute(
            "SELECT * FROM stripe_checkout_intents WHERE user_id = ?", (user_id,)
        )]
        billing_subscriptions = [dict(row) for row in conn.execute(
            "SELECT * FROM alpha_subscriptions WHERE user_id = ?", (user_id,)
        )]
        # Explicit owner predicates prevent an email collision or a third
        # party's referral from leaking into a self-service export.
        account = _rows(conn, "SELECT * FROM users WHERE google_id = ?", (user_id,))
        history = _rows(conn, """SELECT * FROM scan_history WHERE user_id = ? OR
            ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))""", (user_id, email))
        from .history import safe_scan_history_record
        history = [safe_scan_history_record(row) for row in history]
        from .payload_privacy import safe_legacy_scan_value
        for row in scans:
            if row.get("url_found") and ("?" in row["url_found"] or "#" in row["url_found"]):
                row["url_found"] = "[Scan payload list hidden]"
        for row in events:
            row["url_found"] = safe_legacy_scan_value(row.get("url_found"))
        consent = _rows(conn, "SELECT * FROM consent_logs WHERE user_id = ?", (user_id,))
        wallets = _rows(conn, "SELECT * FROM wallets WHERE user_id = ?", (user_id,))
        discord = _rows(conn, "SELECT * FROM discord_links WHERE user_id = ?", (user_id,))
        velocity = _rows(conn, "SELECT * FROM scan_velocity WHERE user_id = ?", (user_id,))
        devices = _rows(conn, "SELECT * FROM device_fingerprints WHERE user_id = ?", (user_id,))
        reports = _rows(conn, """SELECT id, url, reason, risk_score, status, created_at, reviewed_at
            FROM url_reports WHERE lower(reporter_email) = lower(?)""", (email,))
        waitlist = _rows(conn, "SELECT * FROM waitlist_signups WHERE lower(email) = lower(?)", (email,))
        suppressions = _rows(conn, "SELECT * FROM email_suppressions WHERE lower(email) = lower(?)", (email,))
        solana = _rows(conn, "SELECT * FROM alpha_solana_payment_references WHERE user_id = ?", (user_id,))
        sessions = _rows(conn, """SELECT created_at, expires_at, last_active, revoked_at, ip_hash, user_agent
            FROM sessions WHERE google_id = ?""", (user_id,))
        remembered = _rows(conn, """SELECT created_at, expires_at, last_used, revoked_at, ip_hash, user_agent
            FROM persistent_sessions WHERE user_id = ?""", (user_id,))
        challenges = _rows(conn, """SELECT wallet_address, issued_at, expires_at, used, created_at
            FROM wallet_nonces WHERE user_id = ?""", (user_id,))
        age_challenges = _rows(conn, """SELECT return_to, expires_at FROM adult_age_challenges
            WHERE user_id = ?""", (user_id,))
        pending_signins = _rows(conn, """SELECT provider, subject, email, display_name, picture,
            client_kind, return_to, remember_me, expires_at FROM pending_age_signins
            WHERE lower(email) = lower(?)""", (email,))
        local_credentials = _rows(conn, """SELECT email, created_at FROM local_credentials
            WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))""", (user_id, email))
        payment_tokens = _rows(conn, """SELECT purpose, expires_at FROM payment_form_tokens
            WHERE user_id = ?""", (user_id,))
        waitlist_tokens = _rows(conn, """SELECT purpose, created_at, expires_at, used_at
            FROM waitlist_email_tokens WHERE lower(email) = lower(?)""", (email,))
        # These contain anti-abuse evidence, third-party details, credential
        # material, or blob contents. Return only safe metadata and keep the
        # request open for a human to review the withheld fields.
        reviewed = {}
        for label, sql, params in (
            ("auditLogs", "SELECT action, target_type, created_at FROM audit_logs WHERE actor_user_id = ?", (user_id,)),
            ("fraudFlags", "SELECT check_name, severity, reviewed, created_at FROM fraud_flags WHERE user_id = ?", (user_id,)),
            ("abuseFlags", "SELECT flag_type, created_at FROM abuse_flags WHERE lower(email) = lower(?)", (email,)),
            ("ipRegistry", "SELECT event_type, created_at FROM ip_registry WHERE user_id = ?", (user_id,)),
            ("apiKeys", "SELECT name, key_hint, scopes, status, created_at FROM api_keys WHERE created_by = ? OR lower(created_by) = lower(?)", (user_id, email)),
            ("uploadArtifacts", "SELECT content_type, byte_size, sha256, created_at FROM upload_artifacts WHERE user_id = ? OR lower(email) = lower(?)", (user_id, email)),
            ("referrals", "SELECT id, counted, created_at FROM referrals WHERE lower(referrer_email) = lower(?) OR lower(referred_email) = lower(?)", (email, email)),
            ("urlBlocklist", "SELECT id, created_at, removed_at FROM url_blocklist WHERE added_by = ? OR lower(added_by) = lower(?)", (user_id, email)),
        ):
            reviewed[label] = _rows(conn, sql, params)
        review_needed = [label for label, rows in reviewed.items() if rows]
        # The payment provider can hold additional account records that are
        # not in SafeScan's database; never mark this export complete for them.
        if billing_consents or billing_subscriptions:
            review_needed.append("Stripe provider records")
        if solana:
            review_needed.append("Solana payment reconciliation")
    return {"email": email, "scans": scans, "scanEvents": events,
            "dataRequests": requests_, "ageConfirmations": age,
            "ageEligibility": age_eligibility,
            "privacyOptOuts": opt_outs,
            "goGhostSubjects": ghost_subjects, "goGhostConsents": ghost_consents,
            "goGhostRequests": ghost_requests, "goGhostLegacyJobs": ghost_legacy_jobs,
            "billingConsents": billing_consents, "billingSubscriptions": billing_subscriptions,
            "account": account, "scanHistory": history, "consentLogs": consent,
            "wallets": wallets, "discordLinks": discord, "scanVelocity": velocity,
            "deviceFingerprints": devices, "urlReports": reports,
            "waitlistSignups": waitlist, "emailSuppressions": suppressions,
            "solanaPayments": solana, "sessions": sessions,
            "rememberedSessions": remembered, "walletChallenges": challenges,
            "adultAgeChallenges": age_challenges, "pendingAgeSignins": pending_signins,
            "localCredentials": local_credentials, "paymentFormTokens": payment_tokens,
            "waitlistEmailTokens": waitlist_tokens,
            **reviewed, "manualReview": review_needed}

def delete_user_data(email, user_id):
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not unique_email_owner(conn, email, user_id):
            return False
        review_reasons = _erasure_review_reasons(conn, email, user_id)
        # A request can still remove ordinary scan history while payment or
        # audit records wait for review. Keep the account and its sessions so
        # an active subscriber can reach the cancellation portal.
        if review_reasons and set(review_reasons) & {"documented legal hold", "fraud evidence", "abuse evidence"}:
            return False
        for sql in (
            "DELETE FROM scans WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            "DELETE FROM scan_events WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
            "DELETE FROM scan_history WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))",
        ):
            conn.execute(sql, (user_id, email))
        for table in ("go_ghost_requests", "go_ghost_consents", "go_ghost_subjects"):
            if _go_ghost_status_table_exists(conn, table):
                conn.execute(_GO_GHOST_STATUS_SQL[table][1], (user_id,))
        conn.execute("DELETE FROM go_ghost_removal_jobs WHERE user_id = ?", (user_id,))
        if review_reasons:
            return False
        # This path is reachable only when none of the review-only rows above
        # exist. Remove token/session material first so a deleted user cannot
        # continue to authenticate while their account is being removed.
        for sql in (
            "DELETE FROM sessions WHERE google_id = ?",
            "DELETE FROM persistent_sessions WHERE user_id = ?",
            "DELETE FROM discord_links WHERE user_id = ?",
            "DELETE FROM wallet_nonces WHERE user_id = ?",
            "DELETE FROM wallets WHERE user_id = ?",
            "DELETE FROM scan_velocity WHERE user_id = ?",
            "DELETE FROM device_fingerprints WHERE user_id = ?",
            "DELETE FROM payment_form_tokens WHERE user_id = ?",
            "DELETE FROM adult_age_challenges WHERE user_id = ?",
        ):
            conn.execute(sql, (user_id,))
        conn.execute("DELETE FROM local_credentials WHERE user_id = ? OR ((user_id IS NULL OR user_id = '') AND lower(email) = lower(?))", (user_id, email))
        conn.execute("DELETE FROM waitlist_email_tokens WHERE lower(email) = lower(?)", (email,))
        conn.execute("DELETE FROM waitlist_signups WHERE lower(email) = lower(?)", (email,))
        conn.execute("DELETE FROM users WHERE google_id = ?", (user_id,))
        conn.execute("DELETE FROM age_confirmations WHERE email = ?", (email,))
        conn.execute("DELETE FROM age_eligibility WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM pending_age_signins WHERE lower(email) = lower(?)", (email,))
    return True


def correct_display_name(email, user_id, display_name):
    """Correct only the account's display name after signed-in ownership check.

    Provider email, identity, wallet and billing changes need separate review;
    accepting them from an unverified free-text request would allow takeover.
    """
    name = (display_name or "").strip()
    if not name or len(name) > 120 or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return False
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if not unique_email_owner(conn, email, user_id):
            return False
        return conn.execute("UPDATE users SET display_name = ? WHERE google_id = ?", (name, user_id)).rowcount == 1

