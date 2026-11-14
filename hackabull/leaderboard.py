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
    canonical_email_key,
)
from storage import backend_status as storage_backend_status
from storage import download_file as storage_download_file
from storage import object_key as storage_object_key
from storage import upload_bytes as storage_upload_bytes

from safescan_allowlist import should_short_circuit, registrable_domain as allowlist_registrable_domain, is_first_party
import safescan_model_calibration as sm_calibration

# =============================================================================
# LEADERBOARD
# =============================================================================
def public_leaderboard_name(row):
    username = (row.get("username") or "").strip()
    if username:
        return username
    display_name = (row.get("display_name") or "").strip()
    if display_name:
        return display_name[:40]
    email = (row.get("email") or "").strip()
    if "@" in email:
        local, domain = email.split("@", 1)
        local_hint = local[:2] + "***" if len(local) > 2 else "***"
        return f"{local_hint}@{domain}"
    return "SafeScan user"

def get_global_leaderboard(limit=50):
    bounded_limit = max(1, min(int(limit or 50), 100))
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN")
        rows = conn.execute(
            """
            SELECT
                u.google_id AS user_id,
                u.email,
                u.username,
                u.display_name,
                MAX(COALESCE(s.scan_count, 0), COALESCE(se.unique_events, 0), COALESCE(h.total_saved_scans, 0)) AS scan_count,
                COALESCE(h.total_saved_scans, 0) AS total_saved_scans,
                COALESCE(h.last_history_at, se.last_event_at) AS last_scanned_at
            FROM users u
            LEFT JOIN (
                SELECT user_id, MAX(scan_count) AS scan_count
                FROM scans WHERE user_id IS NOT NULL AND user_id != ''
                GROUP BY user_id
            ) s ON s.user_id = u.google_id
            LEFT JOIN (
                SELECT user_id, COUNT(*) AS total_saved_scans, MAX(created_at) AS last_history_at
                FROM scan_history WHERE user_id IS NOT NULL AND user_id != ''
                GROUP BY user_id
            ) h ON h.user_id = u.google_id
            LEFT JOIN (
                SELECT user_id, COUNT(DISTINCT payload_hash) AS unique_events, MAX(first_scanned_at) AS last_event_at
                FROM scan_events WHERE user_id IS NOT NULL AND user_id != ''
                GROUP BY user_id
            ) se ON se.user_id = u.google_id
            WHERE u.status != 'deleted'
              AND MAX(COALESCE(s.scan_count, 0), COALESCE(se.unique_events, 0), COALESCE(h.total_saved_scans, 0)) > 0
            ORDER BY scan_count DESC, total_saved_scans DESC, last_scanned_at DESC
            """,
        ).fetchall()
        # Historical LIMIT 1 backfill makes ID-bound rows untrustworthy for
        # colliding emails. Build the canonical owner map once per page.
        canonical_owners = {}
        for account in conn.execute("SELECT google_id, email FROM users WHERE email IS NOT NULL"):
            key = canonical_email_key(account["email"])
            if key:
                canonical_owners[key] = account["google_id"] if key not in canonical_owners else None
        eligible_rows = []
        for row in rows:
            key = canonical_email_key(row["email"])
            if key and canonical_owners.get(key) == row["user_id"]:
                eligible_rows.append(row)
        rows = eligible_rows
    leaders = []
    for index, row in enumerate(rows[:bounded_limit], start=1):
        item = dict(row)
        item["rank"] = index
        item["public_name"] = public_leaderboard_name(item)
        leaders.append(item)
    return leaders

# Any scanned payload scoring at/above this is treated as malicious (the same
# "high" risk threshold used across the app — see risk_band/status_from_risk).
MALICIOUS_RISK_THRESHOLD = 80

def _like_escape(term):
    # Escape LIKE wildcards so a user's search term is matched literally.
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

