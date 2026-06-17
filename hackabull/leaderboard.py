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
            LEFT JOIN scans s ON s.user_id = u.google_id OR lower(s.email) = lower(u.email)
            LEFT JOIN (
                SELECT user_id, lower(email) AS email_key, COUNT(*) AS total_saved_scans,
                       COUNT(DISTINCT url) AS unique_saved_scans, MAX(created_at) AS last_history_at
                FROM scan_history
                GROUP BY user_id, lower(email)
            ) h ON h.user_id = u.google_id OR h.email_key = lower(u.email)
            LEFT JOIN (
                SELECT lower(email) AS email_key, COUNT(DISTINCT payload_hash) AS unique_events, MAX(first_scanned_at) AS last_event_at
                FROM scan_events
                GROUP BY lower(email)
            ) se ON se.email_key = lower(u.email)
            WHERE u.status != 'deleted'
            GROUP BY u.google_id, u.email, u.username, u.display_name, s.scan_count, h.total_saved_scans, h.unique_saved_scans, h.last_history_at, se.unique_events, se.last_event_at
            HAVING MAX(COALESCE(s.scan_count, 0), COALESCE(se.unique_events, 0), COALESCE(h.total_saved_scans, 0)) > 0
            ORDER BY scan_count DESC, total_saved_scans DESC, last_scanned_at DESC
            LIMIT ?
            """,
            (bounded_limit,)
        ).fetchall()
    leaders = []
    for index, row in enumerate(rows, start=1):
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

