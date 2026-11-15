"""Waitlist consent, purpose-bound email tokens, and suppression state."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from html import escape
from urllib.parse import urlencode, urlparse

from db import get_conn

from .config import APP_URL
from .email_util import email_sending_configured
from .email_util import marketing_email_configured
from .email_util import send_email

WAITLIST_CONSENT_VERSION = "waitlist-updates-v1"
CONFIRM_TTL = timedelta(hours=24)
UNSUBSCRIBE_TTL = timedelta(days=365)
CONFIRM_RESEND_INTERVAL = timedelta(minutes=10)
_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{40,64}\.[0-9a-f]{64}$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _secret() -> bytes | None:
    value = os.getenv("EMAIL_TOKEN_SECRET", "").strip()
    if len(value.encode("utf-8")) < 32 or any(mark in value.lower() for mark in ("replace", "example", "placeholder")):
        return None
    return value.encode("utf-8")


def confirmation_available() -> bool:
    origin = urlparse(APP_URL)
    valid_origin = bool(
        origin.netloc and not origin.path and not origin.query and not origin.fragment
        and (origin.scheme == "https" or (origin.scheme == "http" and origin.hostname in {"localhost", "127.0.0.1", "testserver"}))
    )
    return bool(email_sending_configured() and _secret() and valid_origin)


def _signed_token(purpose: str) -> tuple[str, str]:
    secret = _secret()
    if not secret:
        raise RuntimeError("Email token signing is not configured")
    nonce = secrets.token_urlsafe(32)
    signature = hmac.new(secret, f"{purpose}:{nonce}".encode(), hashlib.sha256).hexdigest()
    return f"{nonce}.{signature}", hashlib.sha256(nonce.encode()).hexdigest()


def _token_hash(token: str, purpose: str) -> str | None:
    secret = _secret()
    if not secret or not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
        return None
    nonce, signature = token.split(".", 1)
    expected = hmac.new(secret, f"{purpose}:{nonce}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    return hashlib.sha256(nonce.encode()).hexdigest()


def _issue(conn, email: str, purpose: str, now: datetime) -> str:
    old_cutoff = _iso(now - timedelta(days=30))
    conn.execute(
        "DELETE FROM waitlist_email_tokens WHERE expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)",
        (old_cutoff, old_cutoff),
    )
    token, token_hash = _signed_token(purpose)
    ttl = CONFIRM_TTL if purpose == "confirm" else UNSUBSCRIBE_TTL
    conn.execute(
        """INSERT INTO waitlist_email_tokens
           (token_hash, email, purpose, created_at, expires_at, used_at)
           VALUES (?, ?, ?, ?, ?, NULL)""",
        (token_hash, email, purpose, _iso(now), _iso(now + ttl)),
    )
    return token


def request_confirmation(email: str, source: str) -> str | None:
    """Capture a pending opt-in and issue a fresh token, or throttle silently.

    Legacy waitlist rows remain unconfirmed; no migration grants consent.
    Suppression remains in force until a new confirmation is consumed.
    """
    if source not in {"footer", "waitlist"}:
        raise ValueError("Unknown waitlist source")
    if not confirmation_available():
        return None
    now = _now()
    stamp = _iso(now)
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT w.confirmed_at, w.last_confirmation_requested_at,
                      s.email AS suppressed_email
               FROM waitlist_signups AS w
               LEFT JOIN email_suppressions AS s ON s.email = w.email
               WHERE w.email = ?""",
            (email,),
        ).fetchone()
        if row and row["confirmed_at"] and not row["suppressed_email"]:
            return None
        last = _read_iso(row["last_confirmation_requested_at"]) if row else None
        if last and now - last < CONFIRM_RESEND_INTERVAL:
            return None
        conn.execute(
            """INSERT INTO waitlist_signups
               (email, source, created_at, consent_at, consent_version, last_confirmation_requested_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(email) DO UPDATE SET
                 source = excluded.source,
                 consent_at = excluded.consent_at,
                 consent_version = excluded.consent_version,
                 last_confirmation_requested_at = excluded.last_confirmation_requested_at""",
            (email, source, stamp, stamp, WAITLIST_CONSENT_VERSION, stamp),
        )
        conn.execute(
            "UPDATE waitlist_email_tokens SET used_at = ? WHERE email = ? AND purpose = 'confirm' AND used_at IS NULL",
            (stamp, email),
        )
        return _issue(conn, email, "confirm", now)


def confirmation_send_failed(email: str, token: str) -> None:
    """Release the resend hold only for the failed request's token."""
    token_hash = _token_hash(token, "confirm")
    if not token_hash:
        return
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT created_at FROM waitlist_email_tokens WHERE token_hash = ? AND email = ? AND used_at IS NULL",
            (token_hash, email),
        ).fetchone()
        if row:
            # SMTP may have accepted the message before the client reported a
            # failure. Keep that link usable if it arrives; a retry replaces it.
            conn.execute(
                """UPDATE waitlist_signups SET last_confirmation_requested_at = NULL
                   WHERE email = ? AND last_confirmation_requested_at = ?""",
                (email, row["created_at"]),
            )


def send_confirmation(email: str, token: str) -> bool:
    url = f"{APP_URL}/waitlist/confirm?{urlencode({'token': token})}"
    safe_url = escape(url, quote=True)
    return send_email(
        email,
        "Confirm your SafeScan QR updates request",
        "<p>Someone requested SafeScan QR product updates for this address.</p>"
        f"<p><a href=\"{safe_url}\">Review and confirm this request</a>.</p>"
        "<p>If this was not you, ignore this message. No updates will be sent unless you confirm.</p>",
        "Someone requested SafeScan QR product updates for this address.\n"
        f"Review and confirm: {url}\n"
        "If this was not you, ignore this message. No updates will be sent unless you confirm.",
        template_id="waitlist_confirmation",
    )


def _valid_row(conn, token: str, purpose: str):
    token_hash = _token_hash(token, purpose)
    if not token_hash:
        return None
    return conn.execute(
        """SELECT token_hash, email, expires_at, used_at
           FROM waitlist_email_tokens WHERE token_hash = ? AND purpose = ?""",
        (token_hash, purpose),
    ).fetchone()


def confirmation_token_valid(token: str) -> bool:
    with get_conn() as conn:
        row = _valid_row(conn, token, "confirm")
    return bool(row and not row["used_at"] and (_read_iso(row["expires_at"]) or datetime.min.replace(tzinfo=timezone.utc)) > _now())


def confirm_subscription(token: str) -> bool:
    now = _now()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _valid_row(conn, token, "confirm")
        if not row or row["used_at"] or (_read_iso(row["expires_at"]) or now) <= now:
            return False
        signup = conn.execute(
            "SELECT consent_at FROM waitlist_signups WHERE email = ?",
            (row["email"],),
        ).fetchone()
        if not signup or not signup["consent_at"]:
            return False
        stamp = _iso(now)
        conn.execute("UPDATE waitlist_email_tokens SET used_at = ? WHERE token_hash = ?", (stamp, row["token_hash"]))
        conn.execute("UPDATE waitlist_signups SET confirmed_at = ? WHERE email = ?", (stamp, row["email"]))
        conn.execute("DELETE FROM email_suppressions WHERE email = ?", (row["email"],))
        return True


def unsubscribe(token: str) -> bool:
    now = _now()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _valid_row(conn, token, "unsubscribe")
        if not row or (_read_iso(row["expires_at"]) or now) <= now:
            return False
        if row["used_at"]:
            return conn.execute("SELECT 1 FROM email_suppressions WHERE email = ?", (row["email"],)).fetchone() is not None
        stamp = _iso(now)
        conn.execute("UPDATE waitlist_email_tokens SET used_at = ? WHERE token_hash = ?", (stamp, row["token_hash"]))
        conn.execute(
            """INSERT INTO email_suppressions (email, suppressed_at, reason)
               VALUES (?, ?, 'unsubscribe')
               ON CONFLICT(email) DO UPDATE SET suppressed_at = excluded.suppressed_at,
                                                reason = excluded.reason""",
            (row["email"], stamp),
        )
        conn.execute(
            "UPDATE waitlist_email_tokens SET used_at = ? WHERE email = ? AND purpose = 'confirm' AND used_at IS NULL",
            (stamp, row["email"]),
        )
        conn.execute(
            "UPDATE waitlist_signups SET last_confirmation_requested_at = NULL WHERE email = ?",
            (row["email"],),
        )
        return True


def send_waitlist_update(email: str, subject: str, html_body: str, text_body: str | None = None) -> bool:
    """Only delivery path for a future product-update campaign."""
    if not marketing_email_configured() or not _secret():
        return False
    with get_conn() as conn:
        row = conn.execute(
            """SELECT 1 FROM waitlist_signups AS w WHERE w.email = ?
               AND w.confirmed_at IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM email_suppressions AS s WHERE s.email = w.email)""",
            (email,),
        ).fetchone()
        if not row:
            return False
        token = _issue(conn, email, "unsubscribe", _now())
    url = f"{APP_URL}/waitlist/unsubscribe?{urlencode({'token': token})}"
    return send_email(
        email, subject, html_body, text_body,
        template_id="waitlist_update", unsubscribe_url=url,
    )
