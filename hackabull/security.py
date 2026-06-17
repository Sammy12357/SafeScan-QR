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
from .audit import SafeScanError
from .audit import audit_log
from .audit import now_iso
from .config import RATE_LIMITS
from .lowlevel import normalize_url
from .request_helpers import make_id
from .request_helpers import request_ip

# =============================================================================
# RATE LIMITING, PAYLOAD VALIDATION & SSRF GUARDS
# =============================================================================
def enforce_rate_limit(request, bucket, limit, window_seconds, user_key=None):
    identity = user_key or request_ip(request)
    key = f"{bucket}:{identity}"
    now = time.time()
    hits = [stamp for stamp in RATE_LIMITS.get(key, []) if now - stamp < window_seconds]
    if len(hits) >= limit:
        retry_after = max(1, int(window_seconds - (now - hits[0])))
        audit_log("auth.rate_limited", request=request, metadata={"bucket": bucket, "retryAfter": retry_after})
        return JSONResponse(
            {"error": "Too many requests", "retryAfter": retry_after},
            status_code=429,
            headers={"Retry-After": str(retry_after)}
        )
    hits.append(now)
    RATE_LIMITS[key] = hits
    return None

def validate_strict_payload(payload, allowed_fields):
    if not isinstance(payload, dict):
        raise SafeScanError("Invalid request.", 400)
    unexpected = set(payload.keys()) - set(allowed_fields)
    if unexpected:
        raise SafeScanError("Unexpected fields: " + ", ".join(sorted(unexpected)), 400)

def is_private_hostname(hostname):
    host = (hostname or "").strip().lower().rstrip(".")
    if not host:
        return True
    if host in ("localhost",) or host.endswith(".localhost") or "render-internal" in host:
        return True
    try:
        ip_values = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ip_values = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
        except socket.gaierror:
            return False
    return any(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast for ip in ip_values)

def validate_public_url(target_url):
    """Normalise and SSRF-check a user-supplied URL before we fetch it.

    Enforces a length cap, an http/https-only scheme, and crucially rejects
    private/localhost/internal hosts so the scanner can't be tricked into
    making requests to internal services. Returns the normalised URL or raises
    SafeScanError(400).
    """
    if not isinstance(target_url, str) or len(target_url.strip()) > 2048:
        raise SafeScanError("URL is required and must be 2048 characters or fewer.", 400)
    normalized = normalize_url(target_url)
    parsed = urlparse(normalized)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SafeScanError("Only valid http and https URLs are supported.", 400)
    if is_private_hostname(parsed.hostname):
        raise SafeScanError("Private, localhost, and internal service URLs are blocked.", 400)
    return normalized

def follow_safe_redirects(target_url, max_redirects=10):
    """Walk a redirect chain manually, re-validating each hop against the SSRF
    guard so a redirect can't bounce us to an internal host. Returns the list of
    responses making up the chain."""
    current = validate_public_url(target_url)
    chain = []
    session = requests.Session()
    for _ in range(max_redirects + 1):
        response = session.get(current, timeout=6, allow_redirects=False, stream=True)
        response.close()
        chain.append(response)
        if response.status_code not in (301, 302, 303, 307, 308):
            return chain
        location = response.headers.get("location")
        if not location:
            return chain
        current = validate_public_url(urljoin(current, location))
    raise requests.TooManyRedirects()

def flag_abuse(email, flag_type, detail):
    with get_conn() as conn:
        conn.execute("INSERT INTO abuse_flags VALUES (?, ?, ?, ?, ?)", (make_id("flag"), email, flag_type, detail, now_iso()))

