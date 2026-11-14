"""Bound outbound threat-intelligence calls without turning skipped checks into CLEAR."""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

from db import get_conn


# A missing or invalid cap fails closed when budgeting is enabled. Keep the
# feature off until the owner has entered contract-appropriate values.
PROVIDER_LIMIT_ENV = {
    "web_risk": "WEB_RISK_MONTHLY_BUDGET",
    "safe_browsing": "SAFE_BROWSING_MONTHLY_BUDGET",
    "phishtank_feed": "PHISHTANK_FEED_MONTHLY_BUDGET",
    "rdap": "RDAP_MONTHLY_BUDGET",
    "whoisxml": "WHOISXML_MONTHLY_BUDGET",
    "securitytrails": "SECURITYTRAILS_MONTHLY_BUDGET",
    "wayback": "WAYBACK_MONTHLY_BUDGET",
}
PROVIDER_CONCURRENCY = {
    "web_risk": 2,
    "safe_browsing": 2,
    "phishtank_feed": 1,
    "rdap": 2,
    "whoisxml": 2,
    "securitytrails": 2,
    "wayback": 2,
}
_SLOTS = {name: threading.BoundedSemaphore(count) for name, count in PROVIDER_CONCURRENCY.items()}
_FAILURE_THRESHOLD = 3
_COOLDOWN_SECONDS = 60


class ProviderUnavailable(RuntimeError):
    """No outbound call was made because the provider guard denied it."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def enabled() -> bool:
    return os.getenv("PROVIDER_BUDGETS_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def _cap(name: str) -> int:
    raw = os.getenv(PROVIDER_LIMIT_ENV[name], "").strip()
    if not raw.isascii() or not raw.isdigit() or len(raw) > 10:
        return 0
    value = int(raw)
    return value if 0 < value <= 1_000_000_000 else 0


def _month(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m")


def _retention_cutoff(month: str) -> str:
    index = int(month[:4]) * 12 + int(month[5:]) - 1 - 23
    year, zero_based_month = divmod(index, 12)
    return f"{year:04d}-{zero_based_month + 1:02d}"


def _ensure_table(conn) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS provider_budget_usage (
            provider TEXT NOT NULL, month TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
            consecutive_failures INTEGER NOT NULL DEFAULT 0, open_until REAL NOT NULL DEFAULT 0,
            PRIMARY KEY(provider, month))"""
    )


def _reserve(name: str, now: float) -> None:
    cap = _cap(name)
    if not cap:
        raise ProviderUnavailable("budget_unconfigured")
    month = _month(now)
    try:
        with get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _ensure_table(conn)
            row = conn.execute(
                "SELECT attempts, open_until FROM provider_budget_usage WHERE provider = ? AND month = ?",
                (name, month),
            ).fetchone()
            if row and float(row["open_until"]) > now:
                raise ProviderUnavailable("circuit_open")
            if row and int(row["attempts"]) >= cap:
                raise ProviderUnavailable("budget_exhausted")
            conn.execute(
                """INSERT INTO provider_budget_usage(provider, month, attempts)
                   VALUES (?, ?, 1)
                   ON CONFLICT(provider, month) DO UPDATE SET attempts = attempts + 1""",
                (name, month),
            )
            # Keep a bounded history for admin cost review across deploys.
            conn.execute("DELETE FROM provider_budget_usage WHERE month < ?", (_retention_cutoff(month),))
    except ProviderUnavailable:
        raise
    except (sqlite3.Error, OSError, RuntimeError) as exc:
        raise ProviderUnavailable("accounting_unavailable") from exc


def _record_outcome(name: str, success: bool, month: str, now: float) -> None:
    try:
        with get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            _ensure_table(conn)
            if success:
                conn.execute(
                    """UPDATE provider_budget_usage
                       SET consecutive_failures = 0, open_until = 0
                       WHERE provider = ? AND month = ?""",
                    (name, month),
                )
            else:
                conn.execute(
                    """UPDATE provider_budget_usage
                       SET failures = failures + 1,
                           consecutive_failures = consecutive_failures + 1,
                           open_until = CASE WHEN consecutive_failures + 1 >= ? THEN ? ELSE open_until END
                       WHERE provider = ? AND month = ?""",
                    (_FAILURE_THRESHOLD, now + _COOLDOWN_SECONDS, name, month),
                )
    except (sqlite3.Error, OSError, RuntimeError) as exc:
        raise ProviderUnavailable("accounting_unavailable") from exc


@contextmanager
def outbound_provider(name: str):
    """Count each attempted network call and open after repeated failures."""
    if not enabled():
        yield
        return
    if name not in PROVIDER_LIMIT_ENV:
        raise ProviderUnavailable("unknown_provider")
    slot = _SLOTS[name]
    if not slot.acquire(blocking=False):
        raise ProviderUnavailable("provider_busy")
    try:
        reserved_at = time.time()
        reserved_month = _month(reserved_at)
        _reserve(name, reserved_at)
        try:
            yield
        except Exception:
            _record_outcome(name, False, reserved_month, time.time())
            raise
        else:
            _record_outcome(name, True, reserved_month, time.time())
    finally:
        slot.release()


def usage_snapshot() -> dict:
    """Fixed-label aggregate counts for owner-only admin views; no URLs or keys."""
    now = time.time()
    month = _month(now)
    rows = {}
    try:
        with get_conn() as conn:
            _ensure_table(conn)
            for row in conn.execute(
                """SELECT provider, attempts, failures, open_until
                   FROM provider_budget_usage WHERE month = ?""",
                (month,),
            ):
                rows[row["provider"]] = row
    except (sqlite3.Error, OSError, RuntimeError):
        return {"enabled": enabled(), "month": month, "state": "unavailable", "providers": {}}
    providers = {}
    for name in PROVIDER_LIMIT_ENV:
        row = rows.get(name)
        providers[name] = {
            "monthlyLimit": _cap(name),
            "attempts": int(row["attempts"]) if row else 0,
            "failures": int(row["failures"]) if row else 0,
            "circuitOpen": bool(row and float(row["open_until"]) > now),
        }
    return {"enabled": enabled(), "month": month, "state": "ready", "providers": providers}
