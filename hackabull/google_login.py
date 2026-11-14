"""Browser-bound, single-use challenges for Google Identity Services redirects."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from db import get_conn


GOOGLE_NONCE_COOKIE = "__Host-safescan_google_nonce"
GOOGLE_NONCE_TTL_SECONDS = 10 * 60
GOOGLE_NONCE_MAX_ACTIVE = 10_000


def _digest(value: str) -> str:
    if not value.isascii():
        raise ValueError("Google login challenge invalid.")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def issue_google_login_challenge(request) -> str:
    nonce = secrets.token_urlsafe(32)
    browser_token = secrets.token_urlsafe(32)
    now = int(time.time())
    with get_conn() as conn:
        conn.execute("DELETE FROM google_login_challenges WHERE created_at < ?", (now - GOOGLE_NONCE_TTL_SECONDS,))
        conn.execute(
            "INSERT INTO google_login_challenges (nonce_hash, browser_hash, created_at) VALUES (?, ?, ?)",
            (_digest(nonce), _digest(browser_token), now),
        )
        active = conn.execute("SELECT COUNT(*) FROM google_login_challenges").fetchone()[0]
        excess = active - GOOGLE_NONCE_MAX_ACTIVE
        if excess > 0:
            conn.execute(
                """DELETE FROM google_login_challenges WHERE nonce_hash IN (
                   SELECT nonce_hash FROM google_login_challenges
                   ORDER BY created_at, rowid LIMIT ?
                )""",
                (excess,),
            )
    request.state.google_login_nonce = nonce
    request.state.google_login_browser_token = browser_token
    return nonce


def set_google_login_cookie(response, request) -> None:
    browser_token = getattr(request.state, "google_login_browser_token", None)
    if browser_token:
        response.set_cookie(
            GOOGLE_NONCE_COOKIE, browser_token, max_age=GOOGLE_NONCE_TTL_SECONDS,
            secure=True, httponly=True, samesite="none", path="/",
        )


def clear_google_login_cookie(response) -> None:
    response.delete_cookie(GOOGLE_NONCE_COOKIE, secure=True, httponly=True, samesite="none", path="/")


def validate_google_csrf(request, csrf_body: str | None) -> None:
    csrf_cookie = request.cookies.get("g_csrf_token")
    if not csrf_cookie or not csrf_body or len(csrf_cookie) > 512 or len(csrf_body) > 512:
        raise ValueError("Google CSRF token mismatch.")
    try:
        if not hmac.compare_digest(csrf_cookie, csrf_body):
            raise ValueError("Google CSRF token mismatch.")
    except TypeError as exc:
        raise ValueError("Google CSRF token invalid.") from exc


def consume_google_login_challenge(request, token_nonce: object, csrf_body: str | None) -> None:
    validate_google_csrf(request, csrf_body)
    browser_token = request.cookies.get(GOOGLE_NONCE_COOKIE)
    if (not browser_token or not isinstance(token_nonce, str) or
            len(browser_token) > 128 or len(token_nonce) > 128):
        raise ValueError("Google login challenge missing.")
    with get_conn() as conn:
        deleted = conn.execute(
            """DELETE FROM google_login_challenges
               WHERE nonce_hash = ? AND browser_hash = ? AND created_at >= ?""",
            (_digest(token_nonce), _digest(browser_token), int(time.time()) - GOOGLE_NONCE_TTL_SECONDS),
        )
        if deleted.rowcount != 1:
            raise ValueError("Google login challenge invalid or already used.")
