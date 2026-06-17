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
from .config import REMEMBER_ME_COOKIE_NAME
from .config import REMEMBER_ME_TTL_SECONDS
from .config import SESSION_COOKIE_NAME
from .config import SESSION_TTL_SECONDS
from .request_helpers import hash_ip
from .request_helpers import make_id
from .request_helpers import request_ip

# =============================================================================
# SESSIONS, COOKIES & "REMEMBER ME" PERSISTENT TOKENS
# =============================================================================
def set_session_cookie(response, session_id):
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

def clear_session_cookie(response):
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
    )

def wants_remember_me(value):
    if value is None:
        return True
    return str(value).strip().lower() not in ("0", "false", "off", "no")

def remember_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def set_remember_me_cookie(response, token):
    response.set_cookie(
        REMEMBER_ME_COOKIE_NAME,
        token,
        max_age=REMEMBER_ME_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

def clear_remember_me_cookie(response):
    response.delete_cookie(
        REMEMBER_ME_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=True,
        samesite="lax",
    )

def create_remember_me_token(user_id, request):
    raw_token = secrets.token_urlsafe(48)
    created = datetime.utcnow()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO persistent_sessions
                (id, user_id, token_hash, created_at, expires_at, last_used, revoked_at, ip_hash, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                make_id("remember"),
                user_id,
                remember_token_hash(raw_token),
                created.isoformat() + "Z",
                (created + timedelta(seconds=REMEMBER_ME_TTL_SECONDS)).isoformat() + "Z",
                created.isoformat() + "Z",
                None,
                hash_ip(request_ip(request)),
                request.headers.get("user-agent", ""),
            ),
        )
    return raw_token

def issue_remember_me_cookie(response, user_id, request):
    set_remember_me_cookie(response, create_remember_me_token(user_id, request))

def validate_and_rotate_remember_me(request):
    raw_token = request.cookies.get(REMEMBER_ME_COOKIE_NAME)
    if not raw_token:
        return None, None
    token_hash = remember_token_hash(raw_token)
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT ps.id AS persistent_session_id, ps.expires_at, ps.revoked_at,
                   u.google_id, u.email, u.username, u.display_name, u.picture,
                   u.role, u.status, u.last_login_at, u.login_ip, u.google_sub
            FROM persistent_sessions ps
            JOIN users u ON u.google_id = ps.user_id
            WHERE ps.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if not row:
            return None, None
        try:
            expires_at = datetime.fromisoformat(str(row["expires_at"]).replace("Z", ""))
        except ValueError:
            conn.execute("UPDATE persistent_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), row["persistent_session_id"]))
            return None, None
        if row["revoked_at"] or expires_at < datetime.utcnow() or row["status"] != "active":
            conn.execute("UPDATE persistent_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?", (now_iso(), row["persistent_session_id"]))
            return None, None

        new_token = secrets.token_urlsafe(48)
        now = datetime.utcnow()
        conn.execute(
            "UPDATE persistent_sessions SET last_used = ?, revoked_at = ? WHERE id = ?",
            (now.isoformat() + "Z", now.isoformat() + "Z", row["persistent_session_id"]),
        )
        conn.execute(
            """
            INSERT INTO persistent_sessions
                (id, user_id, token_hash, created_at, expires_at, last_used, revoked_at, ip_hash, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                make_id("remember"),
                row["google_id"],
                remember_token_hash(new_token),
                now.isoformat() + "Z",
                (now + timedelta(seconds=REMEMBER_ME_TTL_SECONDS)).isoformat() + "Z",
                now.isoformat() + "Z",
                None,
                hash_ip(request_ip(request)),
                request.headers.get("user-agent", ""),
            ),
        )
        user = dict(row)
        user.pop("persistent_session_id", None)
        user.pop("expires_at", None)
        user.pop("revoked_at", None)
        return user, new_token

def revoke_all_remember_me(user_id):
    if not user_id:
        return
    with get_conn() as conn:
        conn.execute(
            "UPDATE persistent_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE user_id = ?",
            (now_iso(), user_id),
        )

def cleanup_persistent_sessions():
    cutoff = now_iso()
    with get_conn() as conn:
        conn.execute("DELETE FROM persistent_sessions WHERE expires_at < ?", (cutoff,))

