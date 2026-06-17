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
from .config import APP_URL
from .config import LOCAL_AUTH_ENABLED

# =============================================================================
# DISCORD ACCOUNT LINKING (OAuth2 + REST role grant)
# Lets a signed-in SafeScan user link their Discord account from the profile
# page. Flow: /auth/discord redirects to Discord's OAuth consent screen ->
# /auth/discord/callback exchanges the code, stores the link, and (when a bot
# token + guild/role ids are configured) auto-joins the user to the server and
# grants the "Verified" role over Discord's REST API — no separate bot process
# required. Everything is optional: without DISCORD_CLIENT_ID/SECRET the
# profile page simply hides the Discord card.
# =============================================================================
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "").strip()
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
DISCORD_GUILD_ID = os.getenv("DISCORD_GUILD_ID", "").strip()
DISCORD_VERIFIED_ROLE_ID = os.getenv("DISCORD_VERIFIED_ROLE_ID", "").strip()
DISCORD_INVITE_URL = os.getenv("DISCORD_INVITE_URL", "https://discord.gg/hqHBQ22z")
DISCORD_API_BASE = "https://discord.com/api/v10"
# HMAC secret for the OAuth state parameter (CSRF protection). Prefers a
# stable configured secret; falls back to a per-boot random value, which is
# fine because a state token only needs to survive the few minutes of one
# OAuth round-trip.
_DISCORD_STATE_SECRET = (os.getenv("SESSION_SECRET") or os.getenv("PRIVACY_HASH_SALT") or secrets.token_hex(32)).strip()


def discord_linking_configured():
    """True when the OAuth app credentials needed for linking are present."""
    return bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET)


def discord_redirect_uri():
    return f"{APP_URL}/auth/discord/callback"


def discord_state_for_user(user_id):
    """Signed, time-stamped state token binding the OAuth flow to this user."""
    payload = f"{user_id}:{int(time.time())}"
    sig = hmac.new(_DISCORD_STATE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode().rstrip("=")


def verify_discord_state(state, max_age_seconds=600):
    """Return the user_id the state was issued for, or None if invalid/expired."""
    try:
        padded = state + "=" * (-len(state) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode()).decode()
        payload_user, ts, sig = decoded.rsplit(":", 2)
        expected = hmac.new(_DISCORD_STATE_SECRET.encode(), f"{payload_user}:{ts}".encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(sig, expected):
            return None
        if time.time() - int(ts) > max_age_seconds:
            return None
        return payload_user
    except Exception:
        return None


def discord_exchange_code(code):
    """Swap the OAuth authorization code for an access token (blocking)."""
    response = requests.post(
        f"{DISCORD_API_BASE}/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": discord_redirect_uri(),
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
        },
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def discord_fetch_identity(access_token):
    """Fetch the linked user's Discord id/username (blocking)."""
    response = requests.get(
        f"{DISCORD_API_BASE}/users/@me",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def discord_join_guild(discord_id, access_token):
    """Add the user to our server using their guilds.join grant. Best-effort:
    returns True when they are (or already were) a member."""
    if not (DISCORD_BOT_TOKEN and DISCORD_GUILD_ID):
        return False
    try:
        response = requests.put(
            f"{DISCORD_API_BASE}/guilds/{DISCORD_GUILD_ID}/members/{discord_id}",
            json={"access_token": access_token},
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            timeout=10,
        )
        return response.status_code in (201, 204)  # 201 = added, 204 = already a member
    except requests.RequestException:
        return False


def discord_grant_verified_role(discord_id):
    """Give the configured Verified role to a guild member. Best-effort."""
    if not (DISCORD_BOT_TOKEN and DISCORD_GUILD_ID and DISCORD_VERIFIED_ROLE_ID):
        return False
    try:
        response = requests.put(
            f"{DISCORD_API_BASE}/guilds/{DISCORD_GUILD_ID}/members/{discord_id}/roles/{DISCORD_VERIFIED_ROLE_ID}",
            headers={"Authorization": f"Bot {DISCORD_BOT_TOKEN}"},
            timeout=10,
        )
        return response.status_code == 204
    except requests.RequestException:
        return False


def get_discord_link(user_id):
    """The user's stored Discord link row as a dict, or None."""
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM discord_links WHERE user_id = ?", (str(user_id),)).fetchone()
    return dict(row) if row else None


_COOKIE_SECURE = not LOCAL_AUTH_ENABLED
_COOKIE_SAMESITE = "lax"

# Session and remember-me cookies use SameSite=Lax (not Strict) so that
# returning users stay signed in: Lax cookies are sent on top-level
# navigations — typing the URL, bookmarks, links from search results or
# email, and the redirect back from Google sign-in — which is exactly when a
# returning visitor should still be recognised. Strict would withhold the
# cookie on those cross-site arrivals and force a fresh login every time. Lax
# still blocks cross-site POSTs, so CSRF protection on state-changing
# endpoints is preserved.
