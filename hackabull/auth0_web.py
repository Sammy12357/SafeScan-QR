"""One-use, browser-bound Auth0 authorization-code transactions for the website."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import time

import requests

from db import get_conn

from .auth0 import verify_auth0_id_token
from .config import APP_URL, AUTH0_ISSUER, AUTH0_WEB_CLIENT_ID, AUTH0_WEB_CLIENT_SECRET


FLOW_COOKIE = "__Host-safescan_auth0_web"
FLOW_SECONDS = 10 * 60


def callback_uri():
    return f"{APP_URL}/auth/auth0/callback"


def _digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def begin_web_flow(return_to, remember):
    cookie = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    with get_conn() as conn:
        conn.execute("DELETE FROM auth0_web_flows WHERE expires_at <= ?", (int(time.time()),))
        conn.execute(
            """INSERT INTO auth0_web_flows
               (cookie_hash, state_hash, nonce, code_verifier, return_to, remember_me, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (_digest(cookie), _digest(state), nonce, verifier, return_to, int(bool(remember)),
             int(time.time()) + FLOW_SECONDS),
        )
    return cookie, state, nonce, challenge


def consume_web_flow(cookie, state):
    # Values are token_urlsafe output. Reject malformed request data before
    # hashing so a non-ASCII cookie or callback state cannot raise a 500.
    if not (isinstance(cookie, str) and isinstance(state, str)
            and re.fullmatch(r"[A-Za-z0-9_-]{40,128}", cookie)
            and re.fullmatch(r"[A-Za-z0-9_-]{40,128}", state)):
        return None
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM auth0_web_flows WHERE cookie_hash = ?", (_digest(cookie),)
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM auth0_web_flows WHERE cookie_hash = ?", (_digest(cookie),))
        if row["expires_at"] <= int(time.time()) or not hmac.compare_digest(row["state_hash"], _digest(state)):
            return None
        return dict(row)


def exchange_web_code(code, code_verifier):
    """Exchange a single-use authorization code; never retain provider tokens."""
    response = requests.post(
        f"{AUTH0_ISSUER}oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": AUTH0_WEB_CLIENT_ID,
            "client_secret": AUTH0_WEB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": callback_uri(),
            "code_verifier": code_verifier,
        },
        timeout=8,
        allow_redirects=False,
    )
    if response.status_code != 200:
        raise ValueError("Auth0 code exchange failed.")
    token = response.json().get("id_token")
    if not isinstance(token, str) or not 100 <= len(token) <= 16000:
        raise ValueError("Auth0 ID token missing or malformed.")
    return token


def web_identity_from_token(token, nonce):
    claims = verify_auth0_id_token(
        token, expected_audiences={AUTH0_WEB_CLIENT_ID}, expected_nonce=nonce
    )
    now = int(time.time())
    expires_at = claims.get("exp")
    issued_at = claims.get("iat")
    if not isinstance(expires_at, int) or expires_at <= now:
        raise ValueError("Auth0 ID token expired.")
    if not isinstance(issued_at, int) or issued_at > now + 60 or issued_at < now - FLOW_SECONDS - 60:
        raise ValueError("Auth0 ID token issued outside the login flow.")
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != AUTH0_WEB_CLIENT_ID:
        raise ValueError("Auth0 ID token authorized party mismatch.")
    if claims.get("email_verified") is not True:
        raise ValueError("A verified Google email is required.")
    subject = claims.get("sub", "")
    if not isinstance(subject, str) or not subject.startswith("google-oauth2|"):
        raise ValueError("Only Auth0's Google connection is accepted.")
    google_id = subject.partition("|")[2]
    if not google_id or len(google_id) > 256:
        raise ValueError("Invalid Google identity.")
    email = claims.get("email", "")
    if not isinstance(email, str) or not email.strip() or len(email) > 320:
        raise ValueError("Invalid verified email.")
    return {
        "provider": "google_auth0_web",
        "subject": google_id,
        "email": email.strip().lower(),
        "display_name": claims.get("name") if isinstance(claims.get("name"), str) else "",
        "picture": claims.get("picture") if isinstance(claims.get("picture"), str) else "",
    }
