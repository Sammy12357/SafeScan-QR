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
from .audit import now_iso
from .config import APP_URL
from .fraud import lookup_user_id_by_email

# =============================================================================
# REFERRALS & UNIQUE-SCAN COUNTING
# =============================================================================
def referral_code_for_user(email):
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        return ""
    with get_conn() as conn:
        row = conn.execute("SELECT referral_code FROM users WHERE email = ?", (normalized_email,)).fetchone()
        if row and row[0]:
            return row[0]
        code = hashlib.sha256(f"{normalized_email}:{APP_URL}".encode("utf-8")).hexdigest()[:10]
        conn.execute("UPDATE users SET referral_code = ? WHERE email = ?", (code, normalized_email))
        return code

def record_unique_scan(email, url, wallet, user_id=None):
    normalized_email = (email or "").strip().lower()
    resolved_user_id = user_id or lookup_user_id_by_email(normalized_email)
    normalized_payload = url.strip()[:2048]
    payload_hash = hashlib.sha256(normalized_payload.encode("utf-8")).hexdigest()
    cutoff = (datetime.utcnow() - timedelta(seconds=60)).isoformat()

    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (email, url_found, scan_count, wallet_address, user_id)
            VALUES (?, ?, 0, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                wallet_address = COALESCE(excluded.wallet_address, scans.wallet_address),
                user_id = COALESCE(scans.user_id, excluded.user_id)
        """, (normalized_email, normalized_payload, wallet, resolved_user_id))

        cursor.execute("SELECT url_found, scan_count FROM scans WHERE email = ?", (normalized_email,))
        previous_url, current_count = cursor.fetchone()

        cursor.execute("""
            INSERT OR IGNORE INTO scan_events (email, payload_hash, url_found, first_scanned_at, user_id)
            VALUES (?, ?, ?, ?, ?)
        """, (normalized_email, payload_hash, normalized_payload, now_iso(), resolved_user_id))

        if cursor.rowcount == 0:
            cursor.execute("SELECT first_scanned_at FROM scan_events WHERE email = ? AND payload_hash = ?", (normalized_email, payload_hash))
            existing = cursor.fetchone()
            if existing and str(existing[0]) >= cutoff:
                return False
            return False

        # Existing rows may already have counted the last scanned payload before
        # scan_events existed. Backfill that event without giving an extra scan.
        previous_urls = [entry.strip() for entry in str(previous_url or "").split(",") if entry.strip()]
        if normalized_payload in previous_urls and current_count > 0:
            cursor.execute("""
                UPDATE scans
                SET wallet_address = COALESCE(?, wallet_address),
                    user_id = COALESCE(user_id, ?)
                WHERE email = ?
            """, (wallet, resolved_user_id, normalized_email))
            return False

        previous_urls.append(normalized_payload)
        updated_urls = ",".join(previous_urls)

        cursor.execute("""
            UPDATE scans
            SET scan_count = scan_count + 1,
                url_found = ?,
                wallet_address = COALESCE(?, wallet_address),
                user_id = COALESCE(user_id, ?),
                airdrop_eligible = CASE WHEN scan_count + 1 >= 5 THEN 1 ELSE airdrop_eligible END
            WHERE email = ?
        """, (updated_urls, wallet, resolved_user_id, normalized_email))
        return True

def get_scan_count(email):
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT scan_count FROM scans WHERE email = ?", (email,))
        result = cursor.fetchone()
        return result[0] if result else 0

