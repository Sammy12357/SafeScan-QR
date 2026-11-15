"""Private Go Ghost status data layer; the HTTP sync API is fixed off.

Only opaque subject IDs and bounded progress codes belong in this database.
The browser profile and broker listing URLs remain on the person's device.
Every query here includes the authenticated account ID explicitly because the
general RLS helper intentionally lets administrators bypass its owner filter.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from removals.registry import broker_metadata


# Compile-time gate. There is deliberately no environment-variable override.
# Cookie-authenticated writes cannot be exposed before session-bound CSRF,
# bounded account rate limits, and a separate extension-auth design exist.
GO_GHOST_STATUS_SYNC_AVAILABLE = False
CONSENT_VERSION = "go-ghost-draft-1"
MAX_SUBJECTS_PER_ACCOUNT = 20
SOURCES = frozenset({"manual", "extension", "mobile"})
FAILURE_CODES = frozenset({
    "network", "layout_changed", "permission_denied", "broker_unavailable", "unknown",
})

# A client report that a listing disappeared is not independent verification.
# No client event can create a verified_removed state.
TRANSITIONS = {
    "start_scan": ({"not_started", "not_found", "failed", "skipped", "still_listed"}, "scanning"),
    "scan_not_found": ({"scanning"}, "not_found"),
    "scan_found": ({"scanning"}, "found"),
    "scan_ambiguous": ({"scanning"}, "needs_review"),
    "mark_not_found": ({"not_started", "scanning", "found", "needs_review", "failed", "skipped"}, "not_found"),
    "start_submit": ({"found", "needs_review"}, "submitting"),
    "needs_human": ({"submitting"}, "needs_human"),
    "resume_submit": ({"needs_human"}, "submitting"),
    "submit_recorded": ({"submitting", "needs_human"}, "submitted"),
    "mark_submitted": ({"not_started", "scanning", "found", "needs_review", "submitting", "needs_human", "failed", "skipped", "still_listed"}, "submitted"),
    "await_email": ({"submitted"}, "awaiting_email"),
    "confirm_email": ({"awaiting_email"}, "confirmed"),
    "begin_recheck": ({"submitted", "awaiting_email", "confirmed", "user_reported_removed", "still_listed", "client_recheck_absent"}, "verifying"),
    "recheck_absent": ({"verifying"}, "client_recheck_absent"),
    "recheck_present": ({"verifying"}, "still_listed"),
    "report_removed": ({"not_started", "submitted", "awaiting_email", "confirmed", "verifying", "still_listed", "failed", "skipped"}, "user_reported_removed"),
    "mark_failed": ({"scanning", "needs_review", "found", "submitting", "needs_human", "submitted", "awaiting_email", "confirmed", "verifying", "still_listed"}, "failed"),
    "mark_skipped": ({"not_started", "not_found", "needs_review", "failed"}, "skipped"),
}


class StatusValidationError(ValueError):
    """Malformed or disallowed status operation (future HTTP 400)."""


class StatusConflictError(ValueError):
    """A stale revision or conflicting subject (future HTTP 409)."""


class SubjectNotFoundError(ValueError):
    """No subject owned by the given account (future HTTP 404)."""


def initialize_status_schema(conn: sqlite3.Connection) -> None:
    """Prepare status tables explicitly in tests; startup never calls this.

    The feature is disabled, so importing or deploying this module must not
    create persistent Go Ghost records or tables. A later rollout migration
    can call this function after the route security gates are satisfied.
    """
    conn.execute('''CREATE TABLE IF NOT EXISTS go_ghost_subjects
                    (subject_id TEXT PRIMARY KEY,
                     user_id TEXT NOT NULL,
                     relationship TEXT NOT NULL CHECK(relationship IN ('self', 'family')),
                     created_at TEXT NOT NULL,
                     UNIQUE(user_id, subject_id),
                     FOREIGN KEY(user_id) REFERENCES users(google_id) ON DELETE CASCADE)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS go_ghost_consents
                    (user_id TEXT NOT NULL,
                     subject_id TEXT NOT NULL,
                     version TEXT NOT NULL,
                     accepted_at TEXT NOT NULL,
                     family_authority_attested_at TEXT,
                     PRIMARY KEY(user_id, subject_id, version),
                     FOREIGN KEY(user_id, subject_id)
                         REFERENCES go_ghost_subjects(user_id, subject_id) ON DELETE CASCADE)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS go_ghost_requests
                    (user_id TEXT NOT NULL,
                     subject_id TEXT NOT NULL,
                     broker_id TEXT NOT NULL,
                     state TEXT NOT NULL CHECK(state IN (
                         'not_started', 'scanning', 'not_found', 'needs_review',
                         'found', 'submitting', 'needs_human', 'submitted',
                         'awaiting_email', 'confirmed', 'verifying',
                         'user_reported_removed', 'client_recheck_absent',
                         'still_listed', 'failed', 'skipped')),
                     source TEXT NOT NULL CHECK(source IN ('manual', 'extension', 'mobile')),
                     failure_code TEXT CHECK(failure_code IN (
                         'network', 'layout_changed', 'permission_denied',
                         'broker_unavailable', 'unknown') OR failure_code IS NULL),
                     recipe_version TEXT,
                     revision INTEGER NOT NULL CHECK(revision > 0),
                     created_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL,
                     submitted_at TEXT,
                     confirmed_at TEXT,
                     next_check_at TEXT,
                     PRIMARY KEY(user_id, subject_id, broker_id),
                     FOREIGN KEY(user_id, subject_id)
                         REFERENCES go_ghost_subjects(user_id, subject_id) ON DELETE CASCADE)''')
    conn.execute("CREATE INDEX IF NOT EXISTS idx_go_ghost_subjects_user ON go_ghost_subjects(user_id)")
    conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS idx_go_ghost_one_self_subject
                    ON go_ghost_subjects(user_id) WHERE relationship = 'self'""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_go_ghost_consents_user ON go_ghost_consents(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_go_ghost_requests_user ON go_ghost_requests(user_id)")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _owner(account_id: str) -> str:
    if not isinstance(account_id, str) or not account_id.strip() or len(account_id) > 255:
        raise StatusValidationError("A canonical account ID is required")
    return account_id


def _active_owner(conn: sqlite3.Connection, account_id: str) -> str:
    account_id = _owner(account_id)
    if conn.execute(
        "SELECT 1 FROM users WHERE google_id = ? AND status = 'active'", (account_id,)
    ).fetchone() is None:
        raise StatusValidationError("An active canonical account is required")
    return account_id


def _subject_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise StatusValidationError("Invalid subject ID") from exc
    if parsed.version != 4 or str(parsed) != value:
        raise StatusValidationError("Invalid subject ID")
    return value


def _exact_object(payload: object, fields: set[str]) -> dict:
    if not isinstance(payload, dict) or set(payload) - fields:
        raise StatusValidationError("Unexpected status fields")
    return payload


def _owned_subject(conn: sqlite3.Connection, account_id: str, subject_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT subject_id, relationship FROM go_ghost_subjects WHERE user_id = ? AND subject_id = ?",
        (_owner(account_id), _subject_id(subject_id)),
    ).fetchone()
    if row is None:
        raise SubjectNotFoundError("Subject not found")
    return row


def create_subject(conn: sqlite3.Connection, account_id: str, payload: object) -> dict:
    """Create an opaque self/family slot, without storing the person's profile."""
    body = _exact_object(payload, {"relationship"})
    relationship = body.get("relationship")
    if relationship not in ("self", "family"):
        raise StatusValidationError("Invalid relationship")
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    account_id = _active_owner(conn, account_id)
    count = conn.execute(
        "SELECT COUNT(*) FROM go_ghost_subjects WHERE user_id = ?", (account_id,)
    ).fetchone()[0]
    if count >= MAX_SUBJECTS_PER_ACCOUNT:
        raise StatusConflictError("Subject limit reached")
    if relationship == "self" and conn.execute(
        "SELECT 1 FROM go_ghost_subjects WHERE user_id = ? AND relationship = 'self'", (account_id,)
    ).fetchone():
        raise StatusConflictError("Self subject already exists")
    subject_id = str(uuid4())
    created_at = _iso(_now())
    conn.execute(
        "INSERT INTO go_ghost_subjects (subject_id, user_id, relationship, created_at) VALUES (?, ?, ?, ?)",
        (subject_id, account_id, relationship, created_at),
    )
    return {"subjectId": subject_id, "relationship": relationship, "createdAt": created_at}


def record_consent(conn: sqlite3.Connection, account_id: str, subject_id: str, payload: object) -> dict:
    """Record the UI's exact consent version and a family authority attestation."""
    body = _exact_object(payload, {"accepted", "familyAuthorityAttested"})
    if body.get("accepted") is not True:
        raise StatusValidationError("Consent must be accepted")
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    account_id = _active_owner(conn, account_id)
    subject = _owned_subject(conn, account_id, subject_id)
    family = subject["relationship"] == "family"
    if family and body.get("familyAuthorityAttested") is not True:
        raise StatusValidationError("Family authority attestation is required")
    if not family and "familyAuthorityAttested" in body:
        raise StatusValidationError("Family attestation is only for family subjects")
    accepted_at = _iso(_now())
    conn.execute(
        """INSERT INTO go_ghost_consents
           (user_id, subject_id, version, accepted_at, family_authority_attested_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(user_id, subject_id, version) DO NOTHING""",
        (account_id, subject_id, CONSENT_VERSION, accepted_at, accepted_at if family else None),
    )
    row = conn.execute(
        """SELECT version, accepted_at, family_authority_attested_at
           FROM go_ghost_consents WHERE user_id = ? AND subject_id = ? AND version = ?""",
        (account_id, subject_id, CONSENT_VERSION),
    ).fetchone()
    return {"version": row["version"], "acceptedAt": row["accepted_at"],
            "familyAuthorityAttestedAt": row["family_authority_attested_at"]}


def list_status(conn: sqlite3.Connection, account_id: str) -> list[dict]:
    """Return only this account's subject IDs, consents, and broker states."""
    if not conn.in_transaction:
        conn.execute("BEGIN")
    account_id = _active_owner(conn, account_id)
    subjects = []
    for row in conn.execute(
        """SELECT s.subject_id, s.relationship, s.created_at,
                  c.version, c.accepted_at, c.family_authority_attested_at
           FROM go_ghost_subjects AS s
           LEFT JOIN go_ghost_consents AS c
             ON c.user_id = s.user_id AND c.subject_id = s.subject_id AND c.version = ?
           WHERE s.user_id = ? ORDER BY s.created_at, s.subject_id""",
        (CONSENT_VERSION, account_id),
    ):
        requests = [dict(item) for item in conn.execute(
            """SELECT broker_id, state, source, failure_code, recipe_version, revision,
                      created_at, updated_at, submitted_at, confirmed_at, next_check_at
               FROM go_ghost_requests
               WHERE user_id = ? AND subject_id = ? ORDER BY broker_id""",
            (account_id, row["subject_id"]),
        )]
        subjects.append({
            "subjectId": row["subject_id"], "relationship": row["relationship"],
            "createdAt": row["created_at"],
            "consent": None if row["version"] is None else {
                "version": row["version"], "acceptedAt": row["accepted_at"],
                "familyAuthorityAttestedAt": row["family_authority_attested_at"],
            },
            "requests": requests,
        })
    return subjects


def apply_client_event(conn: sqlite3.Connection, account_id: str, broker_id: str,
                       payload: object, *, source: str) -> dict:
    """Validate one client claim and atomically advance an owned broker row.

    `source` is supplied by a future authenticated route, never the JSON body.
    This function does not itself make a client an authorized extension.
    """
    body = _exact_object(payload, {"subjectId", "event", "expectedRevision", "failureCode"})
    if not isinstance(source, str) or source not in SOURCES:
        raise StatusValidationError("Invalid source")
    subject_id = _subject_id(body.get("subjectId"))
    broker = broker_metadata(broker_id) if isinstance(broker_id, str) else None
    if broker is None:
        raise StatusValidationError("Unknown broker")
    event = body.get("event")
    if not isinstance(event, str) or len(event) > 48 or (event != "reset" and event not in TRANSITIONS):
        raise StatusValidationError("Unknown event")
    expected_revision = body.get("expectedRevision")
    if type(expected_revision) is not int or not 0 <= expected_revision <= 2**31 - 1:
        raise StatusValidationError("Invalid expected revision")
    failure_code = body.get("failureCode")
    if event == "mark_failed":
        if not isinstance(failure_code, str) or failure_code not in FAILURE_CODES:
            raise StatusValidationError("Invalid failure code")
    elif "failureCode" in body:
        raise StatusValidationError("Failure code is only valid for failure events")
    # Future recipe versions must come from an allowlisted signed manifest,
    # never from an arbitrary client string that could carry personal data.
    recipe_version = None
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    account_id = _active_owner(conn, account_id)
    subject = _owned_subject(conn, account_id, subject_id)
    if subject["relationship"] == "family" and broker["group"] == "peopleconnect":
        raise StatusValidationError("This broker requires a self submission")
    if conn.execute(
        """SELECT 1 FROM go_ghost_consents
           WHERE user_id = ? AND subject_id = ? AND version = ?""",
        (account_id, subject_id, CONSENT_VERSION),
    ).fetchone() is None:
        raise StatusValidationError("Current subject consent is required")
    row = conn.execute(
        """SELECT state, revision, created_at, submitted_at, confirmed_at, next_check_at
           FROM go_ghost_requests WHERE user_id = ? AND subject_id = ? AND broker_id = ?""",
        (account_id, subject_id, broker_id),
    ).fetchone()
    revision = row["revision"] if row else 0
    if revision != expected_revision:
        raise StatusConflictError("Status revision has changed")
    current_state = row["state"] if row else "not_started"
    if event == "reset":
        next_state = "not_started"
    else:
        allowed, next_state = TRANSITIONS[event]
        if current_state not in allowed:
            raise StatusConflictError("Invalid state transition")
    now = _now()
    now_text = _iso(now)
    submitted_at = row["submitted_at"] if row else None
    confirmed_at = row["confirmed_at"] if row else None
    next_check_at = row["next_check_at"] if row else None
    if next_state == "submitted":
        submitted_at = now_text
        confirmed_at = None
        next_check_at = _iso(now + timedelta(days=7))
    elif next_state == "not_started":
        submitted_at = None
        confirmed_at = None
        next_check_at = None
    elif next_state == "confirmed":
        confirmed_at = now_text
    elif event in ("recheck_absent", "recheck_present"):
        next_check_at = None
    elif next_state in ("failed", "skipped", "not_found"):
        next_check_at = None
    if row:
        result = conn.execute(
            """UPDATE go_ghost_requests SET state = ?, source = ?, failure_code = ?,
                      recipe_version = ?, revision = ?, updated_at = ?, submitted_at = ?,
                      confirmed_at = ?, next_check_at = ?
               WHERE user_id = ? AND subject_id = ? AND broker_id = ? AND revision = ?""",
            (next_state, source, failure_code, recipe_version, revision + 1, now_text,
             submitted_at, confirmed_at, next_check_at,
             account_id, subject_id, broker_id, revision),
        )
        if result.rowcount != 1:
            raise StatusConflictError("Status revision has changed")
    else:
        try:
            conn.execute(
                """INSERT INTO go_ghost_requests
                   (user_id, subject_id, broker_id, state, source, failure_code,
                    recipe_version, revision, created_at, updated_at, submitted_at,
                    confirmed_at, next_check_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)""",
                (account_id, subject_id, broker_id, next_state, source, failure_code,
                 recipe_version, now_text, now_text, submitted_at, confirmed_at, next_check_at),
            )
        except sqlite3.IntegrityError as exc:
            raise StatusConflictError("Status revision has changed") from exc
    return {"subjectId": subject_id, "brokerId": broker_id, "state": next_state,
            "source": source, "failureCode": failure_code, "recipeVersion": recipe_version,
            "revision": revision + 1, "updatedAt": now_text,
            "submittedAt": submitted_at, "confirmedAt": confirmed_at,
            "nextCheckAt": next_check_at}
