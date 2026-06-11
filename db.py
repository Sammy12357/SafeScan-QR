"""
Database access layer with application-level row-level security (RLS).

SafeScan stores everything in a single SQLite database. Because SQLite has no
native per-row security, this module emulates it: each request sets a thread-local
"RLS context" (the current user's id, role, and email) via ``set_rls_context``, and
the query helpers (``user_scoped_select`` / ``assert_owns_row``) automatically
filter rows to that user. Admins and owners bypass the filter.

Responsibilities:
  * Resolve which SQLite file to use across local/dev/production (``database_path``).
  * Hand out short-lived, auto-committing connections (``get_conn``).
  * Enforce ownership on reads and writes (the RLS helpers).
"""
from __future__ import annotations
import os
import sqlite3
import threading
from contextlib import contextmanager
from urllib.parse import urlparse, unquote


# Per-thread storage for the "current user" context. Set at the start of each
# request and read by the RLS helpers below so queries stay scoped to one user.
_local = threading.local()

# Maps a table name -> the column that identifies its owning user. Any table
# listed here is user-owned and will be filtered to the current RLS user.
USER_COLUMN = {
    "scans": "email",
    "scan_events": "email",
    "scan_history": "email",
    "sessions": "google_id",
    "wallets": "user_id",
    "wallet_nonces": "user_id",
    "fraud_flags": "user_id",
    "device_fingerprints": "user_id",
    "ip_registry": "user_id",
    "scan_velocity": "user_id",
    "data_requests": "email",
    "age_confirmations": "email",
    "privacy_opt_outs": "email",
    "abuse_flags": "email",
    "consent_logs": "user_id",
    "referrals": "referrer_email",
    "discord_links": "user_id",
}

# Tables with no per-user owner column. These hold global/administrative data,
# so only admins/owners may read them and no user-scoped access is allowed.
ADMIN_ONLY = {
    "audit_logs",
    "url_reports",
    "url_blocklist",
    "breach_reports",
    "api_keys",
    "waitlist_signups",
    "alpha_subscriptions",
    "users",
    "scan_results",
}

# Candidate locations for the SQLite file, in order of preference. The legacy
# path is from an older deploy layout; the default is the current persistent
# disk mount; the local fallback is used for development on a workstation.
LEGACY_SQLITE_PATH = "/app/data/qr_cache.db"
DEFAULT_SQLITE_PATH = "/var/data/qr_cache.db"
LOCAL_FALLBACK_SQLITE_PATH = "qr_cache.db"


def _sqlite_data_weight(path: str) -> int:
    """Rough "how much real data is here" score for a candidate DB file.

    Counts rows across the core tables so we can prefer the database that
    actually contains data when more than one candidate file exists (e.g. after
    a path migration). Returns 0 for a missing or unreadable file.
    """
    if not path or not os.path.exists(path):
        return 0
    try:
        with sqlite3.connect(path) as conn:
            total = 0
            for table in ("users", "scans", "scan_history", "sessions"):
                exists = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (table,),
                ).fetchone()
                if exists:
                    total += int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] or 0)
            return total
    except sqlite3.Error:
        return 0


def _prefer_existing_database(candidate: str) -> str:
    """If the chosen path is one of the standard ones but the *other* standard
    path holds more data, switch to that one. Avoids silently starting against
    an empty database after a deploy that changed the default path."""
    legacy_path = LEGACY_SQLITE_PATH
    default_path = DEFAULT_SQLITE_PATH
    if candidate not in (legacy_path, default_path):
        return candidate
    candidate_weight = _sqlite_data_weight(candidate)
    alternate = legacy_path if candidate == default_path else default_path
    alternate_weight = _sqlite_data_weight(alternate)
    if alternate_weight > candidate_weight:
        return alternate
    return candidate


def _is_production_runtime() -> bool:
    """True when we appear to be running on the live Render deployment."""
    app_url = os.getenv("APP_URL", "").strip().lower()
    environment = os.getenv("ENVIRONMENT", "").strip().lower()
    return (
        bool(os.getenv("RENDER"))
        or environment in ("prod", "production")
        or app_url.startswith("https://safescan-qr.onrender.com")
    )


def _require_persistent_database(path: str) -> str:
    """Guard against accidentally using an ephemeral DB in production.

    On the live deployment a relative (non-absolute) path would live on the
    container's disposable filesystem and be wiped on every restart, silently
    losing user data. Refuse to start in that case unless explicitly overridden.
    """
    if (
        _is_production_runtime()
        and os.getenv("SAFESCAN_ALLOW_EPHEMERAL_DB", "").strip().lower() not in ("1", "true", "yes", "on")
        and not os.path.isabs(path)
    ):
        raise RuntimeError(
            "Production SQLite storage is not configured. Set DATABASE_URL or SQLITE_DB_PATH "
            "to a persistent disk path such as sqlite:////var/data/qr_cache.db."
        )
    return path


def database_path() -> str:
    """Resolve the SQLite file path from configuration, in priority order:

    1. ``DATABASE_URL`` (``sqlite:///...`` form, normalised per-OS)
    2. ``SQLITE_DB_PATH``
    3. ``DATA_DIR`` (file created inside it)
    4. The standard legacy/default disk paths, preferring whichever has data
    5. A local fallback file in the working directory

    Every branch passes through the persistence guard above.
    """
    database_url = os.getenv("DATABASE_URL", "").strip()
    if database_url.startswith("sqlite:///"):
        parsed = urlparse(database_url)
        path = unquote(f"//{parsed.netloc}{parsed.path}") if parsed.netloc else unquote(parsed.path)
        if os.name == "nt":
            path = path.lstrip("/")
        elif path.startswith("//"):
            path = "/" + path.lstrip("/")
        return _require_persistent_database(_prefer_existing_database(path))
    sqlite_path = os.getenv("SQLITE_DB_PATH")
    if sqlite_path:
        return _require_persistent_database(_prefer_existing_database(sqlite_path))
    data_dir = os.getenv("DATA_DIR")
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)
        return _require_persistent_database(_prefer_existing_database(os.path.join(data_dir, "qr_cache.db")))
    if _sqlite_data_weight(LEGACY_SQLITE_PATH) > _sqlite_data_weight(DEFAULT_SQLITE_PATH):
        return _require_persistent_database(LEGACY_SQLITE_PATH)
    if os.path.isdir(os.path.dirname(DEFAULT_SQLITE_PATH)) and os.access(os.path.dirname(DEFAULT_SQLITE_PATH), os.W_OK):
        return _require_persistent_database(DEFAULT_SQLITE_PATH)
    if os.path.exists(LEGACY_SQLITE_PATH) or (os.path.isdir(os.path.dirname(LEGACY_SQLITE_PATH)) and os.access(os.path.dirname(LEGACY_SQLITE_PATH), os.W_OK)):
        return _require_persistent_database(LEGACY_SQLITE_PATH)
    return _require_persistent_database(LOCAL_FALLBACK_SQLITE_PATH)


def database_storage_status() -> dict:
    """Report whether the active DB lives on persistent storage.

    Used by health/admin views to warn operators when the database sits on an
    ephemeral path (where leaderboard, sessions and history would reset on
    redeploy).
    """
    path = database_path()
    absolute_path = os.path.abspath(path)
    persistent_dir = os.path.abspath(os.getenv("PERSISTENT_DATA_DIR", os.path.dirname(DEFAULT_SQLITE_PATH)))
    explicit_persistent = os.getenv("LEADERBOARD_STORAGE_PERSISTENT", "").strip().lower() in {"1", "true", "yes"}
    is_persistent = explicit_persistent or absolute_path == persistent_dir or absolute_path.startswith(persistent_dir + os.sep)
    warning = None
    if not is_persistent:
        warning = (
            "Database is not under persistent storage. Leaderboard, sessions, and scan history "
            "can reset after deploys or restarts."
        )
    return {
        "path": absolute_path,
        "persistent": is_persistent,
        "persistent_dir": persistent_dir,
        "warning": warning,
    }


# --- Row-level-security context -------------------------------------------
# These set/read the current user on the thread. Call set_rls_context() at the
# start of a request and clear_rls_context() when it ends.

def set_rls_context(user_id: str | None, role: str = "user", email: str | None = None):
    """Record the authenticated user for the current thread/request."""
    _local.user_id = user_id
    _local.role = role
    _local.email = email


def clear_rls_context():
    """Reset to an anonymous guest (no user, no elevated role)."""
    _local.user_id = None
    _local.email = None
    _local.role = "guest"


def rls_user_id() -> str | None:
    return getattr(_local, "user_id", None)


def rls_role() -> str:
    return getattr(_local, "role", "guest")


def rls_email() -> str | None:
    return getattr(_local, "email", None)


def is_admin() -> bool:
    return rls_role() in ("admin", "owner")


@contextmanager
def get_conn(row_factory=True):
    """Yield a SQLite connection that commits on success and rolls back on error.

    Usage::

        with get_conn() as conn:
            conn.execute(...)

    Rows come back as ``sqlite3.Row`` (dict-like) unless ``row_factory=False``.
    """
    conn = sqlite3.connect(database_path(), check_same_thread=False)
    if row_factory:
        conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _where_clause(extra_where: str) -> str:
    """Prefix a caller-supplied condition with WHERE, or return '' if empty."""
    return f"WHERE {extra_where}" if extra_where else ""


def user_scoped_select(conn, table: str, extra_where: str = "", params: tuple = ()):
    """
    Return rows filtered to the current RLS user unless the current role is
    admin/owner. Tables without user ownership are admin-only.
    """
    if table in ADMIN_ONLY:
        if not is_admin():
            raise PermissionError(f"Table '{table}' requires admin role.")
        return conn.execute(f"SELECT * FROM {table} {_where_clause(extra_where)}", params).fetchall()

    col = USER_COLUMN.get(table)
    if not col:
        raise ValueError(f"Unknown table: {table}")

    if is_admin():
        return conn.execute(f"SELECT * FROM {table} {_where_clause(extra_where)}", params).fetchall()

    uid = rls_user_id()
    if not uid:
        return []

    # Scan tables are special: historically rows were keyed by email, but newer
    # rows carry a user_id. Match on either so a user sees their whole history
    # regardless of which scheme wrote the row. scan_events only has an email.
    email = rls_email()
    if table in ("scans", "scan_events", "scan_history"):
        owner_clause = "email = ?"
        owner_params = [uid]
        if email and email != uid:
            owner_clause = "(user_id = ? OR lower(email) = lower(?))" if table != "scan_events" else "lower(email) = lower(?)"
            owner_params = [uid, email] if table != "scan_events" else [email]
        elif table != "scan_events":
            owner_clause = "(user_id = ? OR email = ?)"
            owner_params = [uid, uid]
        if extra_where:
            return conn.execute(
                f"SELECT * FROM {table} WHERE {owner_clause} AND ({extra_where})",
                (*owner_params, *params),
            ).fetchall()
        return conn.execute(f"SELECT * FROM {table} WHERE {owner_clause}", tuple(owner_params)).fetchall()

    if extra_where:
        return conn.execute(
            f"SELECT * FROM {table} WHERE {col} = ? AND ({extra_where})",
            (uid, *params),
        ).fetchall()
    return conn.execute(f"SELECT * FROM {table} WHERE {col} = ?", (uid,)).fetchall()


def assert_owns_row(conn, table: str, row_id: str):
    """
    Raise PermissionError when the current RLS user does not own the row.
    Admins and owners bypass the ownership check.
    """
    if is_admin():
        return

    if table in ADMIN_ONLY:
        raise PermissionError(f"Table '{table}' requires admin role.")

    uid = rls_user_id()
    if not uid:
        raise PermissionError("Authentication required.")

    col = USER_COLUMN.get(table)
    if not col:
        raise ValueError(f"Unknown table: {table}")

    if table in ("scans", "scan_history"):
        row = conn.execute(f"SELECT email, user_id FROM {table} WHERE id = ?", (row_id,)).fetchone()
        email = rls_email()
        if row and (str(row["user_id"] or "") == str(uid) or (email and str(row["email"]).lower() == str(email).lower())):
            return
        raise PermissionError("You do not own this resource.")

    row = conn.execute(f"SELECT {col} FROM {table} WHERE id = ?", (row_id,)).fetchone()
    if not row or str(row[col]) != str(uid):
        raise PermissionError("You do not own this resource.")
