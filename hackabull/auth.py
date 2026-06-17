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
from .audit import audit_log
from .audit import now_iso
from .config import SESSION_COOKIE_NAME
from .config import SESSION_IDLE_SECONDS
from .config import SESSION_TTL_SECONDS
from .request_helpers import hash_ip
from .request_helpers import request_ip
from .sessions import validate_and_rotate_remember_me

# =============================================================================
# CURRENT-USER RESOLUTION & ROLE CHECKS
# =============================================================================
def request_session_id(request):
    auth_header = request.headers.get("authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return request.cookies.get(SESSION_COOKIE_NAME)

def create_session(google_id, request):
    session_id = secrets.token_urlsafe(32)
    created = datetime.utcnow()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                google_id,
                created.isoformat() + "Z",
                (created + timedelta(seconds=SESSION_TTL_SECONDS)).isoformat() + "Z",
                created.isoformat() + "Z",
                None,
                hash_ip(request_ip(request)),
                request.headers.get("user-agent", ""),
            )
        )
    return session_id

def get_session_user(request):
    if getattr(request.state, "session_user_loaded", False):
        return getattr(request.state, "session_user", None)

    def cache_session_user(user):
        request.state.session_user_loaded = True
        request.state.session_user = user
        return user

    remembered_user = getattr(request.state, "remembered_user", None)
    if remembered_user and remembered_user.get("status") == "active":
        return cache_session_user(remembered_user)

    session_id = request_session_id(request)
    if not session_id:
        remembered_user, rotated_token = validate_and_rotate_remember_me(request)
        if remembered_user:
            request.state.remembered_user = remembered_user
            request.state.remembered_session_id = create_session(remembered_user["google_id"], request)
            request.state.rotated_remember_token = rotated_token
            return cache_session_user(remembered_user)
        return cache_session_user(None)
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT s.id AS session_id, s.expires_at, s.last_active, s.revoked_at,
                   u.google_id, u.email, u.username, u.display_name, u.picture,
                   u.role, u.status, u.last_login_at, u.login_ip
            FROM sessions s
            JOIN users u ON u.google_id = s.google_id
            WHERE s.id = ?
            """,
            (session_id,)
        ).fetchone()
        if not row:
            return cache_session_user(None)
        try:
            expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", ""))
            last_active = datetime.fromisoformat(str(row["last_active"]).replace("Z", ""))
        except ValueError:
            return cache_session_user(None)
        if row["revoked_at"] or expires_at < datetime.utcnow() or datetime.utcnow() - last_active > timedelta(seconds=SESSION_IDLE_SECONDS):
            conn.execute("UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), session_id))
            return cache_session_user(None)
        if row["status"] != "active":
            return cache_session_user(None)
        conn.execute("UPDATE sessions SET last_active = ? WHERE id = ?", (now_iso(), session_id))
        return cache_session_user(dict(row))

def require_user(request):
    """Return the authenticated user for this request or raise HTTP 401.

    Use this in routes that must not be reached anonymously.
    """
    user = get_session_user(request)
    if not user:
        audit_log("auth.failed", request=request)
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user

def require_user_from_google_id(google_id):
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT google_id, email, username, display_name, picture, role, status, google_sub FROM users WHERE google_id = ?", (google_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return dict(row)

def has_role(user, role):
    hierarchy = ["guest", "user", "admin", "owner"]
    return hierarchy.index(user.get("role", "guest")) >= hierarchy.index(role)

def require_role_user(request, role):
    user = require_user(request)
    if not has_role(user, role):
        audit_log("auth.permission_denied", request=request, actor_user_id=user.get("google_id"), metadata={"requiredRole": role})
        raise HTTPException(status_code=403, detail="You do not have permission to do this.")
    return user

