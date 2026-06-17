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
from .config import AIRDROP_ADMIN_SECRET

# =============================================================================
# RESULT CACHE & REQUEST HELPERS (IP, locale, ids)
# =============================================================================
def get_cached_result(target_url: str):
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT status, timestamp FROM scan_results WHERE url = ?", (target_url,))
        row = cursor.fetchone()
    if row:
        last_scan = datetime.fromisoformat(row[1])
        if datetime.now() - last_scan < timedelta(hours=24):
            return row[0]
    return None

def save_to_cache(target_url: str, status: str):
    with get_conn() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO scan_results VALUES (?, ?, ?)", (target_url, status, datetime.now().isoformat()))

def make_id(prefix):
    return f"{prefix}_{hashlib.sha256(f'{prefix}:{datetime.utcnow().isoformat()}:{os.urandom(8)}'.encode('utf-8')).hexdigest()[:24]}"

def hash_ip(ip_value):
    salt = os.getenv("PRIVACY_HASH_SALT", "safescan-dev-salt")
    return hashlib.sha256(f"{salt}:{ip_value or 'unknown'}".encode("utf-8")).hexdigest()

def request_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def locale_from_request(request: Request):
    return (request.headers.get("accept-language") or "en-US").split(",")[0].strip()

def is_eu_locale(locale):
    return locale.lower().split("-")[-1] in {
        "at", "be", "bg", "hr", "cy", "cz", "dk", "ee", "fi", "fr", "de", "gr",
        "hu", "ie", "it", "lv", "lt", "lu", "mt", "nl", "pl", "pt", "ro", "sk",
        "si", "es", "se", "is", "li", "no"
    }

def is_california_locale_or_region(request: Request, region: str = ""):
    return region.lower() in ("ca", "california") or "california" in region.lower()

def admin_authorized(secret):
    return bool(AIRDROP_ADMIN_SECRET and secret == AIRDROP_ADMIN_SECRET)

