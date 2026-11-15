"""Published document snapshots and explicit account agreement records.

An OAuth identity may reach these helpers only after its provider token has
been verified. A pending ticket is a short-lived continuation, not a session.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

from db import get_conn

from .config import ADMIN_EMAIL
from .request_helpers import hash_ip, request_ip


PUBLISHED = Path(__file__).resolve().parent / "legal_published"
DOCUMENTS = {
    "terms": {
        "title": "Terms of Use",
        "current": "v1.1",
        "versions": {"v1.0": "May 2026", "v1.1": "November 15, 2026"},
    },
    "privacy": {
        "title": "Privacy Policy",
        "current": "v1.1",
        "versions": {"v1.0": "May 2026", "v1.1": "November 15, 2026"},
    },
    "cookie": {
        "title": "Cookie Policy",
        "current": "v1.0",
        "versions": {"v1.0": "May 2026"},
    },
}
ACCEPTANCE_DOCUMENTS = ("terms", "privacy")
TERMS_COOKIE = "__Host-safescan_pending_terms"
PENDING_SECONDS = 10 * 60


def _now():
    return datetime.now(timezone.utc)


def _stamp(value):
    return value.isoformat().replace("+00:00", "Z")


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def current_versions():
    return {document: DOCUMENTS[document]["current"] for document in ACCEPTANCE_DOCUMENTS}


def published_document(document, version=None):
    metadata = DOCUMENTS.get(document)
    if not metadata:
        return None
    selected = version or metadata["current"]
    if selected not in metadata["versions"]:
        return None
    body = (PUBLISHED / f"{document}.{selected}.html").read_text(encoding="utf-8")
    if document == "privacy" and selected == metadata["current"]:
        body = body.replace("{{SAFESCAN_ADMIN_EMAIL}}", escape(ADMIN_EMAIL, quote=True))
    return {
        "title": metadata["title"],
        "version": selected,
        "last_updated": metadata["versions"][selected],
        "body_html": body,
    }


def acceptance_is_current(user_id):
    if not user_id:
        return False
    with get_conn() as conn:
        accepted = {
            (row[0], row[1]) for row in conn.execute(
                "SELECT document, version FROM terms_acceptances WHERE user_id = ?",
                (user_id,),
            )
        }
    return all((document, version) in accepted for document, version in current_versions().items())


def identity_has_current_acceptance(subject):
    """Provider identity only; an email match cannot inherit agreement proof."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT google_id FROM users WHERE (google_id = ? OR google_sub = ?) AND status = 'active' LIMIT 1",
            (subject, subject),
        ).fetchone()
    return bool(row and acceptance_is_current(row[0]))


def validate_acceptance(consent, terms_version, privacy_version):
    versions = current_versions()
    if consent is not True or terms_version != versions["terms"] or privacy_version != versions["privacy"]:
        raise ValueError("Review and agree to the current Terms of Use and Privacy Policy.")
    return versions


def record_acceptance(user_id, request, versions):
    """Persist exactly the documents displayed before issuing a session."""
    if not user_id or versions != current_versions():
        raise ValueError("The agreement has changed. Review the current documents.")
    accepted_at = _stamp(_now())
    ip_hash = hash_ip(request_ip(request))
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        for document, version in versions.items():
            conn.execute(
                """INSERT OR IGNORE INTO terms_acceptances
                   (user_id, document, version, accepted_at, ip_hash)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, document, version, accepted_at, ip_hash),
            )


def begin_terms_sign_in(identity, *, client_kind, return_to="/", remember=True):
    """Create a one-use continuation for a verified, age-eligible identity."""
    if client_kind not in ("web", "mobile") or not identity.get("subject") or not identity.get("email"):
        raise ValueError("Verified sign-in identity required.")
    ticket = secrets.token_urlsafe(32)
    now = _now()
    with get_conn() as conn:
        conn.execute("DELETE FROM pending_terms_signins WHERE expires_at <= ?", (_stamp(now),))
        conn.execute(
            """INSERT INTO pending_terms_signins
               (ticket_hash, provider, subject, email, display_name, picture,
                client_kind, return_to, remember_me, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (_digest(ticket), identity["provider"], identity["subject"], identity["email"],
             (identity.get("display_name") or "")[:120], (identity.get("picture") or "")[:500],
             client_kind, return_to, int(bool(remember)), _stamp(now + timedelta(seconds=PENDING_SECONDS))),
        )
    return ticket


def pending_terms_sign_in(ticket, client_kind):
    if not ticket or len(ticket) > 128 or client_kind not in ("web", "mobile"):
        return None
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """SELECT * FROM pending_terms_signins
               WHERE ticket_hash = ? AND client_kind = ? AND expires_at > ?""",
            (_digest(ticket), client_kind, _stamp(_now())),
        ).fetchone()
    return dict(row) if row else None


def consume_terms_sign_in(ticket, client_kind):
    if not ticket or len(ticket) > 128 or client_kind not in ("web", "mobile"):
        return None
    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT * FROM pending_terms_signins
               WHERE ticket_hash = ? AND client_kind = ? AND expires_at > ?""",
            (_digest(ticket), client_kind, _stamp(_now())),
        ).fetchone()
        if not row:
            return None
        conn.execute("DELETE FROM pending_terms_signins WHERE ticket_hash = ?", (_digest(ticket),))
    return dict(row)
