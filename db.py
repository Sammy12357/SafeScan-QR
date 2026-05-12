import os
import sqlite3
import threading
from contextlib import contextmanager
from urllib.parse import urlparse, unquote


_local = threading.local()

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
}

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

LEGACY_SQLITE_PATH = "/app/data/qr_cache.db"
DEFAULT_SQLITE_PATH = "/var/data/qr_cache.db"


def _sqlite_data_weight(path: str) -> int:
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


def database_path() -> str:
    database_url = os.getenv("DATABASE_URL", "").strip()
    if database_url.startswith("sqlite:///"):
        parsed = urlparse(database_url)
        path = unquote(f"//{parsed.netloc}{parsed.path}") if parsed.netloc else (unquote(parsed.path.lstrip("/")) if os.name == "nt" else unquote(parsed.path))
        return _prefer_existing_database(path)
    data_dir = os.getenv("DATA_DIR")
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)
        return _prefer_existing_database(os.path.join(data_dir, "qr_cache.db"))
    sqlite_path = os.getenv("SQLITE_DB_PATH")
    if sqlite_path:
        return _prefer_existing_database(sqlite_path)
    if _sqlite_data_weight(LEGACY_SQLITE_PATH) > _sqlite_data_weight(DEFAULT_SQLITE_PATH):
        return LEGACY_SQLITE_PATH
    if os.path.isdir(os.path.dirname(DEFAULT_SQLITE_PATH)) and os.access(os.path.dirname(DEFAULT_SQLITE_PATH), os.W_OK):
        return DEFAULT_SQLITE_PATH
    if os.path.exists(LEGACY_SQLITE_PATH) or (os.path.isdir(os.path.dirname(LEGACY_SQLITE_PATH)) and os.access(os.path.dirname(LEGACY_SQLITE_PATH), os.W_OK)):
        return LEGACY_SQLITE_PATH
    return "qr_cache.db"


def set_rls_context(user_id: str | None, role: str = "user", email: str | None = None):
    _local.user_id = user_id
    _local.role = role
    _local.email = email


def clear_rls_context():
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
