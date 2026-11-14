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
from .client_ip import request_ip

# =============================================================================
# REQUEST HELPERS (IP, locale, ids)
# =============================================================================
def make_id(prefix):
    # A URL-safe 128-bit random suffix keeps externally visible scan, report,
    # and data-request identifiers unguessable without changing their prefix.
    return f"{prefix}_{secrets.token_urlsafe(16)}"

def validate_privacy_hash_salt():
    """Refuse the development IP hash key when serving production traffic.

    Length and variety catch placeholders, but operators must still generate a
    random secret and keep it stable; this check cannot prove entropy.
    """
    production = bool(os.getenv("RENDER")) or os.getenv("ENVIRONMENT", "").strip().lower() in ("prod", "production")
    configured_salt = os.getenv("PRIVACY_HASH_SALT", "")
    salt = configured_salt.strip()
    if production and (
        len(salt) < 32
        or len(set(salt)) < 8
        or configured_salt != salt
        or any(marker in salt.lower() for marker in ("safescan-dev", "replace-with", "placeholder", "change-me"))
    ):
        raise RuntimeError("Production requires a stable, randomly generated PRIVACY_HASH_SALT of at least 32 characters")

def hash_ip(ip_value):
    validate_privacy_hash_salt()
    salt = os.getenv("PRIVACY_HASH_SALT", "safescan-dev-salt")
    return hashlib.sha256(f"{salt}:{ip_value or 'unknown'}".encode("utf-8")).hexdigest()

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
    return bool(
        AIRDROP_ADMIN_SECRET and len(AIRDROP_ADMIN_SECRET) >= 32 and secret and
        hmac.compare_digest(secret, AIRDROP_ADMIN_SECRET)
    )

