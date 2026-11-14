"""Session-bound CSRF tokens for browser mutations.

For a signed-in browser, the token is derived from its active random session
credential. Anonymous form pages use an independent host-only random cookie.
Only a same-origin page can read the rendered token; the cookie is HttpOnly.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from urllib.parse import urlsplit

from fastapi import Form, HTTPException, Request
from jinja2 import pass_context

from .config import ALLOWED_ORIGINS
from .config import REMEMBER_ME_COOKIE_NAME
from .config import SESSION_COOKIE_NAME


CSRF_COOKIE_NAME = "__Host-safescan_csrf"
CSRF_COOKIE_MAX_AGE = 24 * 60 * 60
CSRF_EXEMPT_PATHS = {"/auth/google", "/webhooks/stripe", "/api/telemetry/scan", "/api/security/csp-report"}


def _cookie_key(request: Request) -> str | None:
    restored_session = getattr(request.state, "remembered_session_id", None)
    for prefix, candidate in (
        ("session", restored_session),
        ("session", request.cookies.get(SESSION_COOKIE_NAME)),
        ("remember", request.cookies.get(REMEMBER_ME_COOKIE_NAME)),
        ("guest", request.cookies.get(CSRF_COOKIE_NAME)),
    ):
        if isinstance(candidate, str) and 16 <= len(candidate) <= 128 and candidate.isascii():
            return f"{prefix}:{candidate}"
    return None


def _token_for_key(key: str) -> str:
    return hmac.new(key.encode("ascii"), b"safescan-csrf-v1", hashlib.sha256).hexdigest()


def prepare_csrf_token(request: Request) -> None:
    key = _cookie_key(request)
    if key is None and request.method in {"GET", "HEAD"}:
        guest_secret = secrets.token_urlsafe(32)
        request.state.csrf_guest_secret = guest_secret
        key = f"guest:{guest_secret}"
    request.state.csrf_token = _token_for_key(key) if key else ""


def bind_csrf_to_new_session(request: Request, session_id: str) -> None:
    """Use the new cookie's token when login renders HTML in the same response."""
    request.state.csrf_token = _token_for_key(f"session:{session_id}")


def set_guest_csrf_cookie(response, request: Request) -> None:
    guest_secret = getattr(request.state, "csrf_guest_secret", None)
    if guest_secret:
        response.set_cookie(
            CSRF_COOKIE_NAME, guest_secret, max_age=CSRF_COOKIE_MAX_AGE,
            secure=True, httponly=True, samesite="lax", path="/",
        )


@pass_context
def csrf_token(context) -> str:
    request = context.get("request")
    return getattr(request.state, "csrf_token", "") if request else ""


def _origin_of(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme not in {"https", "http"} or not parsed.netloc or parsed.username or parsed.password:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _browser_origin_allowed(request: Request) -> bool:
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site and fetch_site != "same-origin":
        return False
    origin = request.headers.get("origin")
    if origin:
        return origin in ALLOWED_ORIGINS
    referer = request.headers.get("referer")
    if referer:
        return _origin_of(referer) in ALLOWED_ORIGINS
    return fetch_site == "same-origin"


def _bearer_only(request: Request) -> bool:
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return (
        scheme.lower() == "bearer" and bool(token.strip())
        and not request.cookies.get(SESSION_COOKIE_NAME)
        and not request.cookies.get(REMEMBER_ME_COOKIE_NAME)
    )


def browser_csrf_required(request: Request) -> bool:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    if request.url.path in CSRF_EXEMPT_PATHS or _bearer_only(request):
        return False
    return any(request.cookies.get(name) for name in (
        SESSION_COOKIE_NAME, REMEMBER_ME_COOKIE_NAME, CSRF_COOKIE_NAME,
    ))


def check_browser_origin(request: Request) -> None:
    if browser_csrf_required(request) and not _browser_origin_allowed(request):
        raise HTTPException(status_code=403, detail="CSRF check failed.")


def _check_token(request: Request, supplied: str | None) -> None:
    key = _cookie_key(request)
    if not key or not isinstance(supplied, str) or len(supplied) != 64:
        raise HTTPException(status_code=403, detail="CSRF check failed.")
    if not hmac.compare_digest(_token_for_key(key), supplied):
        raise HTTPException(status_code=403, detail="CSRF check failed.")


def require_csrf_header(request: Request) -> None:
    if browser_csrf_required(request):
        _check_token(request, request.headers.get("x-csrf-token"))


def require_csrf_form(request: Request, csrf_token: str | None = Form(None)) -> None:
    if not _bearer_only(request):
        _check_token(request, csrf_token)


def require_same_origin_action(request: Request) -> None:
    """Require explicit same-origin evidence for sensitive admin actions."""
    origin = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if (
        (fetch_site and fetch_site != "same-origin")
        or (origin and origin not in ALLOWED_ORIGINS)
        or (not origin and fetch_site != "same-origin")
    ):
        raise HTTPException(status_code=403, detail="You do not have permission to do this.")
