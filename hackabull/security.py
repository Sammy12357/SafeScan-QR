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
import certifi
import urllib3
from requests.structures import CaseInsensitiveDict

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
    raw = target_url.strip()
    # normalize_url adds https:// to bare domains. Do not let it turn an
    # unsupported redirect scheme such as ftp:// into a plausible HTTPS URL.
    if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.IGNORECASE) and not re.match(r"^https?://", raw, re.IGNORECASE):
        raise SafeScanError("Only valid http and https URLs are supported.", 400)
    normalized = normalize_url(target_url)
    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        parsed.port  # Reject malformed/out-of-range ports before any fetch.
    except ValueError:
        raise SafeScanError("URL has an invalid hostname or port.", 400) from None
    if parsed.scheme not in ("http", "https") or not hostname:
        raise SafeScanError("Only valid http and https URLs are supported.", 400)
    if username is not None or password is not None:
        raise SafeScanError("URLs containing username or password are not supported.", 400)
    try:
        ascii_host = hostname.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        raise SafeScanError("URL has an invalid hostname.", 400) from None
    if is_private_hostname(ascii_host):
        raise SafeScanError("Private, localhost, and internal service URLs are blocked.", 400)
    return normalized


def _public_address_for_connection(hostname, port):
    """Resolve once, reject every non-public answer, and return a pinned IP."""
    host = (hostname or "").strip().lower().rstrip(".")
    if not host or host == "localhost" or host.endswith(".localhost") or "render-internal" in host:
        raise SafeScanError("Private, localhost, and internal service URLs are blocked.", 400)
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise requests.ConnectionError(f"DNS resolution failed: {type(exc).__name__}") from exc
        addresses = list(dict.fromkeys(ipaddress.ip_address(info[4][0]) for info in answers))
    if not addresses:
        raise requests.ConnectionError("DNS returned no addresses.")
    if any(not address.is_global for address in addresses):
        raise SafeScanError("Private, localhost, and internal service URLs are blocked.", 400)
    return str(addresses[0])


def _fetch_pinned_url(target_url, timeout):
    """Fetch headers through a validated IP while keeping the URL hostname for TLS.

    Direct urllib3 pools deliberately ignore environment proxy settings: a
    proxy must not re-resolve an attacker-controlled hostname after validation.
    Only response headers are needed to trace redirects; never download a page.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    try:
        ascii_host = hostname.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        raise SafeScanError("URL has an invalid hostname.", 400) from None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    pinned_ip = _public_address_for_connection(ascii_host, port)
    default_port = 443 if parsed.scheme == "https" else 80
    host_label = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    host_header = host_label if port == default_port else f"{host_label}:{port}"
    request_target = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    pool_options = {"port": port, "retries": False}
    if parsed.scheme == "https":
        pool = urllib3.HTTPSConnectionPool(
            pinned_ip,
            server_hostname=ascii_host,
            assert_hostname=ascii_host,
            cert_reqs="CERT_REQUIRED",
            ca_certs=certifi.where(),
            **pool_options,
        )
    else:
        pool = urllib3.HTTPConnectionPool(pinned_ip, **pool_options)
    try:
        raw_response = pool.urlopen(
            "GET",
            request_target,
            headers={"Host": host_header, "User-Agent": "SafeScan-QR/1.0"},
            redirect=False,
            retries=False,
            preload_content=False,
            assert_same_host=False,
            timeout=urllib3.Timeout(total=timeout, connect=min(3, timeout), read=min(3, timeout)),
        )
        try:
            response = requests.Response()
            response.status_code = raw_response.status
            response.url = target_url
            response.headers = CaseInsensitiveDict(raw_response.headers.items())
            response._content_consumed = True
            return response
        finally:
            raw_response.close()
            raw_response.release_conn()
    except (urllib3.exceptions.HTTPError, OSError, UnicodeError, ValueError) as exc:
        raise requests.ConnectionError(f"Pinned fetch failed: {type(exc).__name__}") from exc
    finally:
        pool.close()

def follow_safe_redirects(target_url, max_redirects=10):
    """Walk a redirect chain manually, re-validating each hop against the SSRF
    guard so a redirect can't bounce us to an internal host. Returns the list of
    responses making up the chain."""
    current = validate_public_url(target_url)
    chain = []
    deadline = time.monotonic() + 20
    for _ in range(min(max_redirects, 10) + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise requests.Timeout("Redirect inspection exceeded 20 seconds.")
        response = _fetch_pinned_url(current, timeout=min(6, remaining))
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

