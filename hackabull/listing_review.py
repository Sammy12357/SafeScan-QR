"""Evidence and dispute helpers for the public QR URL observation board.

Only apex domains from administrator-added blocklist rows can be published.
Disputes and evidence remain staff-only except for source category, time, and
the fact that a listing is under review.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import re
import sqlite3

from .audit import now_iso
from .malicious_db import _public_domain
from .request_helpers import make_id


SOURCE_LABELS = {
    "admin_review": "SafeScan administrator review",
    "safescan_analysis": "SafeScan URL analysis reviewed by an administrator",
}
SOURCE_CHOICES = frozenset(SOURCE_LABELS)


def public_listing_id(domain: str) -> str:
    return hashlib.sha256(domain.encode("ascii")).hexdigest()[:16]


def listing_rows(conn: sqlite3.Connection, listing_id: str, *, include_removed: bool = False):
    """Resolve an opaque public ID to its confirmed apex domain and rows."""
    if not re.fullmatch(r"[0-9a-f]{16}", listing_id or ""):
        return None, []
    where = "" if include_removed else "WHERE removed_at IS NULL"
    rows = conn.execute(
        f"SELECT id, url, reason, added_by, created_at, removed_at FROM url_blocklist {where} ORDER BY created_at DESC"
    ).fetchall()
    matches = []
    domain = None
    for row in rows:
        row = dict(row)
        candidate = _public_domain(row["url"])
        if candidate and public_listing_id(candidate) == listing_id:
            matches.append(row)
            domain = candidate
    return domain, matches


def evidence_note(value: str) -> str | None:
    note = (value or "").strip()
    if not 20 <= len(note) <= 500 or any(ord(char) < 32 and char not in "\r\n\t" for char in note):
        return None
    return note


def record_listing_evidence(
    conn: sqlite3.Connection,
    block_id: str,
    *,
    source: str,
    observation: str,
    source_ref: str,
    recorded_by: str,
) -> None:
    """Persist the independent/admin observation behind a publication decision."""
    if source not in SOURCE_CHOICES or evidence_note(observation) is None:
        raise ValueError("Listing evidence is incomplete")
    observed_at = now_iso()
    conn.execute(
        """INSERT INTO listing_evidence
           (id, block_id, source, source_ref, observation, observed_at, recorded_at, recorded_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (make_id("evidence"), block_id, source, source_ref, observation.strip(),
         observed_at, observed_at, recorded_by),
    )


def first_response_due(created_at: str) -> str:
    """Two business days, excluding weekends; holidays require manual review."""
    try:
        current = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    except (TypeError, ValueError, AttributeError):
        return "Unknown"
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    days = 0
    while days < 2:
        current += timedelta(days=1)
        if current.weekday() < 5:
            days += 1
    return current.astimezone(timezone.utc).date().isoformat()


def dispute_detail(conn: sqlite3.Connection, listing_id: str) -> dict | None:
    domain, blocks = listing_rows(conn, listing_id, include_removed=True)
    if not domain:
        return None
    evidence_rows = conn.execute(
        """SELECT e.*, b.url, b.removed_at FROM listing_evidence e
           JOIN url_blocklist b ON b.id = e.block_id
           ORDER BY e.observed_at DESC"""
    ).fetchall()
    block_ids = {block["id"] for block in blocks}
    evidence = [dict(row) for row in evidence_rows if row["block_id"] in block_ids]
    # Older decisions predate evidence capture. Show their actual metadata to
    # staff without inventing a provider match or an observation they lacked.
    evidenced = {row["block_id"] for row in evidence}
    for block in blocks:
        if block["id"] not in evidenced:
            evidence.append({
                "block_id": block["id"], "source": "legacy_admin_record",
                "source_ref": None, "observation": block["reason"] or "No reason recorded",
                "observed_at": block["created_at"], "recorded_by": block["added_by"] or "Unknown",
                "url": block["url"], "removed_at": block["removed_at"],
            })
    disputes = [dict(row) for row in conn.execute(
        "SELECT * FROM listing_disputes WHERE domain = ? ORDER BY created_at DESC LIMIT 100",
        (domain,),
    )]
    for row in disputes:
        row["first_response_due"] = first_response_due(row["created_at"])
    return {"id": listing_id, "domain": domain, "blocks": blocks,
            "evidence": evidence, "disputes": disputes,
            "active": any(block["removed_at"] is None for block in blocks)}
