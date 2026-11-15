"""Narrow retention jobs for periods already stated in published policy.

This does not erase accounts or payment records. Those require a billing and
legal-hold reconciliation before unattended deletion can be safe.
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timedelta, timezone

from db import get_conn
from .payload_privacy import is_web_url_payload, minimize_url_text, private_history_signals, safe_legacy_scan_value


def scrub_legacy_scan_storage() -> dict[str, int]:
    """Remove raw query values and old private QR payloads from scan tables.

    Unique-scan events containing raw queries are discarded; their aggregate
    `scans.scan_count` remains. Subsequent scans use query-free references.
    This runs at startup, so it also repairs an interrupted earlier run.
    """
    changed = {"scan_history": 0, "scan_events": 0, "scans": 0, "scan_velocity": 0}
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            "SELECT id, url, signals, risk_score FROM scan_history WHERE instr(url, '?') > 0 OR instr(url, '#') > 0 OR instr(signals, '?') > 0 OR (url NOT LIKE 'http%' AND url NOT LIKE '[%')"
        ).fetchall()
        for row in rows:
            url = row["url"] or ""
            minimized = safe_legacy_scan_value(url)
            if is_web_url_payload(url):
                signals = minimize_url_text(row["signals"] or "[]")
            else:
                signals = json.dumps(private_history_signals(None, int(row["risk_score"] or 0)))
            if minimized == url and signals == (row["signals"] or "[]"):
                continue
            conn.execute("UPDATE scan_history SET url = ?, signals = ? WHERE id = ?", (minimized, signals, row["id"]))
            changed["scan_history"] += 1
        changed["scan_events"] = conn.execute(
            "DELETE FROM scan_events WHERE instr(url_found, '?') > 0 OR instr(url_found, '#') > 0 OR (url_found NOT LIKE 'http%' AND url_found NOT LIKE '[%')"
        ).rowcount
        changed["scans"] = conn.execute(
            "UPDATE scans SET url_found = '' WHERE url_found != '' AND (instr(url_found, '?') > 0 OR instr(url_found, '#') > 0 OR (url_found NOT LIKE 'http%' AND url_found NOT LIKE '[%'))"
        ).rowcount
        velocities = conn.execute(
            "SELECT user_id, last_scan_url FROM scan_velocity WHERE last_scan_url IS NOT NULL AND (instr(last_scan_url, '?') > 0 OR instr(last_scan_url, '#') > 0 OR (last_scan_url NOT LIKE 'http%' AND last_scan_url NOT LIKE '[%'))"
        ).fetchall()
        for row in velocities:
            conn.execute("UPDATE scan_velocity SET last_scan_url = ? WHERE user_id = ?", (safe_legacy_scan_value(row["last_scan_url"]), row["user_id"]))
            changed["scan_velocity"] += 1
    return changed


def _five_year_cutoff(now: datetime) -> datetime:
    try:
        return now.replace(year=now.year - 5)
    except ValueError:  # 29 February when the target year is not a leap year
        return now.replace(year=now.year - 5, day=28)


def run_retention(now: datetime | None = None) -> dict[str, int]:
    """Delete expired consent proofs and disposable URL-result cache rows.

    `RETENTION_LEGAL_HOLD=true` suspends consent deletion during a documented
    investigation. It does not disable cache expiry, which holds no raw URL.
    The caller can inject a clock for deterministic tests.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Retention clock must be timezone-aware")
    now = now.astimezone(timezone.utc)
    cache_cutoff = (now - timedelta(hours=24)).replace(tzinfo=None).isoformat()
    consent_cutoff = _five_year_cutoff(now).replace(tzinfo=None).isoformat() + "Z"
    with get_conn() as conn:
        conn.execute("BEGIN IMMEDIATE")
        cache_count = conn.execute(
            "DELETE FROM scan_results WHERE timestamp < ?", (cache_cutoff,)
        ).rowcount
        consent_count = 0
        if os.getenv("RETENTION_LEGAL_HOLD", "").strip().lower() not in {"1", "true", "yes"}:
            consent_count = conn.execute(
                "DELETE FROM consent_logs WHERE timestamp < ?", (consent_cutoff,)
            ).rowcount
    return {"scan_results": cache_count, "consent_logs": consent_count}
