"""One-time email confirmation for the public waitlist."""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone

from db import get_conn


CONFIRM_COOKIE = "__Host-safescan_waitlist_confirm"
CONFIRM_SECONDS = 30 * 60
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def valid_token(token: object) -> bool:
    return isinstance(token, str) and bool(_TOKEN_RE.fullmatch(token))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def issue_confirmation(email: str) -> str | None:
    """Return a raw one-time token, or None for an already confirmed address."""
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = _now()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM waitlist_confirmation_tokens WHERE expires_at <= ?", (now.isoformat(),))
        confirmed = conn.execute(
            "SELECT 1 FROM waitlist_signups WHERE email = ? AND confirmed_at IS NOT NULL", (email,)
        ).fetchone()
        if confirmed:
            return None
        conn.execute(
            """INSERT INTO waitlist_confirmation_tokens (email, token_hash, created_at, expires_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(email) DO UPDATE SET token_hash = excluded.token_hash,
                   created_at = excluded.created_at, expires_at = excluded.expires_at""",
            (email, token_hash, now.isoformat(), (now + timedelta(seconds=CONFIRM_SECONDS)).isoformat()),
        )
    return token


def revoke_unsent_confirmation(email: str, token: str) -> None:
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM waitlist_confirmation_tokens WHERE email = ? AND token_hash = ?",
            (email, token_hash),
        )


def confirm_waitlist(token: object) -> bool:
    """Consume a valid unexpired token exactly once and mark the address confirmed."""
    if not valid_token(token):
        return False
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = _now()
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT email, expires_at FROM waitlist_confirmation_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if not row:
            return False
        conn.execute("DELETE FROM waitlist_confirmation_tokens WHERE token_hash = ?", (token_hash,))
        try:
            expires = datetime.fromisoformat(row["expires_at"])
        except (TypeError, ValueError):
            return False
        if expires.tzinfo is None or expires <= now:
            return False
        already_confirmed = conn.execute(
            "SELECT 1 FROM waitlist_signups WHERE email = ? AND confirmed_at IS NOT NULL",
            (row["email"],),
        ).fetchone()
        if already_confirmed:
            return False
        conn.execute(
            """INSERT INTO waitlist_signups (email, source, created_at, confirmed_at)
               VALUES (?, 'footer', ?, ?)
               ON CONFLICT(email) DO UPDATE SET confirmed_at = excluded.confirmed_at""",
            (row["email"], now.isoformat(), now.isoformat()),
        )
    return True
