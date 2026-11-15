"""Server-owned age challenges. Birth year and birthday answer are never saved."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from db import get_conn


ACCOUNT_MIN_AGE = 16
ADULT_MIN_AGE = 18
PENDING_SECONDS = 10 * 60
GUEST_ADULT_SECONDS = 24 * 60 * 60
DENIAL_SECONDS = 24 * 60 * 60
PENDING_COOKIE = "__Host-safescan_pending_age"
ADULT_CHALLENGE_COOKIE = "__Host-safescan_adult_challenge"
GUEST_ADULT_COOKIE = "__Host-safescan_adult_guest"


def _now():
    return datetime.now(timezone.utc)


def _stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity_digest(provider, subject):
    salt = os.getenv("PRIVACY_HASH_SALT", "safescan-dev-salt").encode("utf-8")
    # Web Google, mobile Google and Auth0's Google connection can all resolve
    # to the same subject. A denial must apply across those entry points.
    canonical = subject if str(subject).startswith("auth0:") else f"google:{subject}"
    return hmac.new(salt, f"age:{canonical}".encode("utf-8"), hashlib.sha256).hexdigest()


def age_from_year(birth_year, birthday_this_year, *, today=None):
    """Calculate age without retaining a birth date or the answer."""
    year_text = str(birth_year).strip()
    if not year_text.isascii() or not year_text.isdecimal() or len(year_text) != 4:
        raise ValueError("Enter a four-digit birth year.")
    year = int(year_text)
    today = today or _now().date()
    if year < 1900 or year > today.year:
        raise ValueError("Enter a valid birth year.")
    if birthday_this_year not in ("yes", "no"):
        raise ValueError("Choose whether your birthday has occurred this year.")
    # The answer is only used in this calculation and is not persisted.
    return today.year - year - (birthday_this_year == "no")


def _resolved_identity(conn, subject, email):
    """Find only a matching provider identity; never merge by email alone."""
    row = conn.execute(
        "SELECT google_id, status FROM users WHERE google_id = ? OR google_sub = ? LIMIT 1",
        (subject, subject),
    ).fetchone()
    if row:
        return row[0], row[1]
    collision = conn.execute(
        "SELECT google_id FROM users WHERE lower(email) = lower(?) AND status != 'deleted' LIMIT 1",
        (email,),
    ).fetchone()
    if collision:
        raise ValueError("This email is already linked to a different sign-in identity.")
    return None, None


def eligible_account(provider, subject, email):
    with get_conn() as conn:
        user_id, status = _resolved_identity(conn, subject, email)
        if status and status != "active":
            raise ValueError("Account is unavailable.")
        if not user_id:
            return False
        row = conn.execute(
            "SELECT minimum_age FROM age_eligibility WHERE user_id = ?", (user_id,)
        ).fetchone()
        return bool(row and row[0] >= ACCOUNT_MIN_AGE)


def begin_sign_in(provider, subject, email, display_name="", picture="", *, client_kind, return_to="/", remember=True):
    """Return a one-time bearer ticket, or None for an already eligible user."""
    if not subject or not email or client_kind not in ("web", "mobile"):
        raise ValueError("Verified sign-in identity required.")
    now = _now()
    with get_conn() as conn:
        user_id, status = _resolved_identity(conn, subject, email)
        if status and status != "active":
            raise ValueError("Account is unavailable.")
        if user_id:
            eligible = conn.execute(
                "SELECT 1 FROM age_eligibility WHERE user_id = ? AND minimum_age >= ?",
                (user_id, ACCOUNT_MIN_AGE),
            ).fetchone()
            if eligible:
                return None
        identity_hash = _identity_digest(provider, subject)
        blocked = conn.execute(
            "SELECT 1 FROM age_denials WHERE identity_hash = ? AND expires_at > ?",
            (identity_hash, _stamp(now)),
        ).fetchone()
        if blocked:
            raise ValueError("Age eligibility cannot be retried yet.")
        conn.execute("DELETE FROM pending_age_signins WHERE expires_at <= ?", (_stamp(now),))
        conn.execute("DELETE FROM age_denials WHERE expires_at <= ?", (_stamp(now),))
        ticket = secrets.token_urlsafe(32)
        conn.execute(
            """INSERT INTO pending_age_signins
               (ticket_hash, provider, subject, email, display_name, picture,
                client_kind, return_to, remember_me, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (_digest(ticket), provider, subject, email, display_name[:120], picture[:500],
             client_kind, return_to, int(bool(remember)), _stamp(now + timedelta(seconds=PENDING_SECONDS))),
        )
    return ticket


def pending_sign_in(ticket, client_kind):
    if not ticket or len(ticket) > 128:
        return None
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM pending_age_signins WHERE ticket_hash = ? AND client_kind = ? AND expires_at > ?",
            (_digest(ticket), client_kind, _stamp(_now())),
        ).fetchone()
    return dict(row) if row else None


def consume_sign_in(ticket, client_kind, age):
    if not ticket or len(ticket) > 128:
        return None
    now = _now()
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM pending_age_signins WHERE ticket_hash = ? AND client_kind = ? AND expires_at > ?",
            (_digest(ticket), client_kind, _stamp(now)),
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM pending_age_signins WHERE ticket_hash = ?", (_digest(ticket),))
        if age < ACCOUNT_MIN_AGE:
            conn.execute(
                "INSERT OR REPLACE INTO age_denials (identity_hash, expires_at) VALUES (?, ?)",
                (_identity_digest(row["provider"], row["subject"]), _stamp(now + timedelta(seconds=DENIAL_SECONDS))),
            )
        return dict(row)


def record_account_eligibility(user_id):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO age_eligibility (user_id, minimum_age, confirmed_at, adult_attested_at)
               VALUES (?, ?, ?, NULL)
               ON CONFLICT(user_id) DO UPDATE SET
                 minimum_age = MAX(age_eligibility.minimum_age, excluded.minimum_age),
                 confirmed_at = age_eligibility.confirmed_at""",
            (user_id, ACCOUNT_MIN_AGE, _stamp(_now())),
        )


def account_is_eligible(user_id):
    with get_conn() as conn:
        return bool(conn.execute(
            "SELECT 1 FROM age_eligibility WHERE user_id = ? AND minimum_age >= ?",
            (user_id, ACCOUNT_MIN_AGE),
        ).fetchone())


def account_is_adult(user_id):
    with get_conn() as conn:
        return bool(conn.execute(
            "SELECT 1 FROM age_eligibility WHERE user_id = ? AND minimum_age >= ? AND adult_attested_at IS NOT NULL",
            (user_id, ADULT_MIN_AGE),
        ).fetchone())


def record_adult_attestation(user_id):
    with get_conn() as conn:
        conn.execute(
            """UPDATE age_eligibility SET minimum_age = ?, adult_attested_at = ?
               WHERE user_id = ? AND minimum_age >= ?""",
            (ADULT_MIN_AGE, _stamp(_now()), user_id, ACCOUNT_MIN_AGE),
        )
        if conn.total_changes != 1:
            raise ValueError("Account age confirmation required.")


def create_adult_challenge(user_id, return_to):
    ticket = secrets.token_urlsafe(32)
    with get_conn() as conn:
        conn.execute("DELETE FROM adult_age_challenges WHERE expires_at <= ?", (_stamp(_now()),))
        conn.execute(
            "INSERT INTO adult_age_challenges VALUES (?, ?, ?, ?)",
            (_digest(ticket), user_id, return_to, _stamp(_now() + timedelta(seconds=PENDING_SECONDS))),
        )
    return ticket


def consume_adult_challenge(ticket, user_id):
    if not ticket or len(ticket) > 128:
        return None
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT return_to FROM adult_age_challenges WHERE ticket_hash = ? AND user_id IS ? AND expires_at > ?",
            (_digest(ticket), user_id, _stamp(_now())),
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM adult_age_challenges WHERE ticket_hash = ?", (_digest(ticket),))
    return row[0]


def create_guest_adult_ticket():
    ticket = secrets.token_urlsafe(32)
    with get_conn() as conn:
        conn.execute("DELETE FROM guest_adult_tickets WHERE expires_at <= ?", (_stamp(_now()),))
        conn.execute(
            "INSERT INTO guest_adult_tickets VALUES (?, ?)",
            (_digest(ticket), _stamp(_now() + timedelta(seconds=GUEST_ADULT_SECONDS))),
        )
    return ticket


def guest_is_adult(ticket):
    if not ticket or len(ticket) > 128:
        return False
    with get_conn() as conn:
        return bool(conn.execute(
            "SELECT 1 FROM guest_adult_tickets WHERE ticket_hash = ? AND expires_at > ?",
            (_digest(ticket), _stamp(_now())),
        ).fetchone())
