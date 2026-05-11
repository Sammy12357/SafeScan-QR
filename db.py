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
    "users",
    "scan_results",
}


def database_path() -> str:
    database_url = os.getenv("DATABASE_URL", "").strip()
    if database_url.startswith("sqlite:///"):
        parsed = urlparse(database_url)
        if parsed.netloc:
            return unquote(f"//{parsed.netloc}{parsed.path}")
        return unquote(parsed.path.lstrip("/")) if os.name == "nt" else unquote(parsed.path)
    data_dir = os.getenv("DATA_DIR")
    if data_dir:
        return os.path.join(data_dir, "qr_cache.db")
    sqlite_path = os.getenv("SQLITE_DB_PATH")
    if sqlite_path:
        return sqlite_path
    if os.path.isdir("/var/data") and os.access("/var/data", os.W_OK):
        return "/var/data/qr_cache.db"
    return "qr_cache.db"


def set_rls_context(user_id: str | None, role: str = "user"):
    _local.user_id = user_id
    _local.role = role


def clear_rls_context():
    _local.user_id = None
    _local.role = "guest"


def rls_user_id() -> str | None:
    return getattr(_local, "user_id", None)


def rls_role() -> str:
    return getattr(_local, "role", "guest")


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

    row = conn.execute(f"SELECT {col} FROM {table} WHERE id = ?", (row_id,)).fetchone()
    if not row or str(row[col]) != str(uid):
        raise PermissionError("You do not own this resource.")
