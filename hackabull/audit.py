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
from .config import ADMIN_EMAILS
from .config import OWNER_EMAILS
from .request_helpers import make_id
from .request_helpers import request_ip

# =============================================================================
# ERRORS, AUDIT LOGGING & METADATA HELPERS
# =============================================================================
class SafeScanError(Exception):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

def iso_from_unix_timestamp(value):
    if value in (None, ""):
        return None
    try:
        return datetime.utcfromtimestamp(int(value)).isoformat() + "Z"
    except (TypeError, ValueError, OSError):
        return None

def role_for_email(email):
    normalized = (email or "").strip().lower()
    if normalized in OWNER_EMAILS:
        return "owner"
    if normalized in ADMIN_EMAILS:
        return "admin"
    return "user"

def sanitize_metadata(value):
    blocked = ("password", "token", "secret", "key", "hash", "credential")
    if isinstance(value, dict):
        return {
            key: sanitize_metadata(item)
            for key, item in value.items()
            if not any(term in str(key).lower() for term in blocked)
        }
    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value]
    return value

def audit_log(action, request=None, actor_user_id=None, target_type=None, target_id=None, metadata=None):
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    make_id("audit"),
                    actor_user_id,
                    action,
                    target_type,
                    target_id,
                    json.dumps(sanitize_metadata(metadata or {})),
                    request_ip(request) if request else None,
                    request.headers.get("user-agent", "") if request else None,
                    now_iso(),
                )
            )
    except sqlite3.Error:
        pass

