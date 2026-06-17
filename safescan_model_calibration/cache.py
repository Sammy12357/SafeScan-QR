from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

LOG = logging.getLogger(__name__)
from .decision import interpret_probability
from .features import _normalize_url

# -----------------------------------------------------------------------------
# 3. URL prediction cache (SQLite, TTL-based with split benign/malicious)
# -----------------------------------------------------------------------------

# Single TTL kept for backwards compat (used as the BENIGN TTL default).
_CACHE_TTL_SECONDS = int(os.getenv("SAFESCAN_ML_CACHE_TTL", str(60 * 60)))
# Benign verdicts are stable: a legitimately good URL stays good for hours.
_CACHE_TTL_BENIGN = int(os.getenv("SAFESCAN_ML_CACHE_TTL_BENIGN", str(_CACHE_TTL_SECONDS)))
# Malicious/suspicious verdicts expire fast so takedowns and re-classification
# after a feature/threshold tune are picked up quickly.
_CACHE_TTL_MALICIOUS = int(os.getenv("SAFESCAN_ML_CACHE_TTL_MALICIOUS", str(15 * 60)))
_CACHE_PATH = os.getenv("SAFESCAN_ML_CACHE_PATH", os.path.join(os.getenv("DATA_DIR", "/tmp"), "ml_cache.sqlite"))
_CACHE_ENABLED = os.getenv("SAFESCAN_ML_CACHE_ENABLED", "true").lower() in ("1", "true", "yes", "on")
_cache_lock = threading.Lock()
_cache_conn: Optional[sqlite3.Connection] = None


def _cache_connection() -> Optional[sqlite3.Connection]:
    """Lazy-init the SQLite cache, swallow errors so a broken cache never
    breaks the analyzer."""
    global _cache_conn
    if not _CACHE_ENABLED:
        return None
    if _cache_conn is not None:
        return _cache_conn
    with _cache_lock:
        if _cache_conn is not None:
            return _cache_conn
        try:
            os.makedirs(os.path.dirname(_CACHE_PATH) or ".", exist_ok=True)
            conn = sqlite3.connect(_CACHE_PATH, check_same_thread=False, isolation_level=None)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS ml_cache (
                    url_key   TEXT PRIMARY KEY,
                    payload   TEXT NOT NULL,
                    cached_at INTEGER NOT NULL
                )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ml_cache_age ON ml_cache(cached_at)")
            _cache_conn = conn
            LOG.info("ML prediction cache ready at %s", _CACHE_PATH)
            return _cache_conn
        except Exception as exc:  # pragma: no cover - defensive
            LOG.warning("ML cache unavailable: %s", exc)
            return None


def _normalize_cache_key(url: str) -> str:
    """Use the same normalization the URL classifier sees so http/https
    variants share a row (the trained model is scheme-agnostic)."""
    return _normalize_url(url)


def _ttl_for_payload(payload: dict) -> int:
    """Choose TTL based on the cached payload's bucket. Defaults to benign
    TTL when the bucket field is missing."""
    bucket = (payload or {}).get("bucket") or ""
    if bucket in ("malicious", "suspicious", "uncertain"):
        return _CACHE_TTL_MALICIOUS
    return _CACHE_TTL_BENIGN


def _reband_payload(payload: dict) -> dict:
    """Re-derive bucket/severity/label/trustSignal from the cached raw
    probability so threshold tweaks take effect without flushing the cache.

    Cached payloads written by older versions lack `rawMaliciousProbability`
    and `lexicalBonus`; in that case we fall back to `maliciousProbability`
    (already adjusted) which preserves the original behavior.
    """
    if not isinstance(payload, dict):
        return payload
    raw = payload.get("rawMaliciousProbability")
    bonus = payload.get("lexicalBonus", 0.0)
    if raw is None:
        adjusted = payload.get("maliciousProbability")
        if adjusted is None:
            return payload
        adjusted_prob = float(adjusted)
    else:
        adjusted_prob = max(0.0, min(1.0, float(raw) + float(bonus or 0.0)))

    decision = interpret_probability(adjusted_prob)
    updated = dict(payload)
    updated.update({
        "trustSignal": decision.trust_signal,
        "score": round(adjusted_prob * 100.0, 1),
        "label": decision.label,
        "bucket": decision.bucket,
        "severity": decision.severity,
        "benignProbability": round(1.0 - adjusted_prob, 4),
        "maliciousProbability": round(adjusted_prob, 4),
        "raw": [round(1.0 - adjusted_prob, 6), round(adjusted_prob, 6)],
    })
    return updated


def cache_get(url: str) -> Optional[dict]:
    """Return the cached prediction for `url`, or None if absent or expired.

    Uses per-bucket TTLs and re-applies the current calibration bands to
    the stored raw probability before returning, so threshold changes
    don't require flushing.
    """
    if not url:
        return None
    conn = _cache_connection()
    if conn is None:
        return None
    key = _normalize_cache_key(url)
    try:
        row = conn.execute(
            "SELECT payload, cached_at FROM ml_cache WHERE url_key = ?",
            (key,),
        ).fetchone()
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("ML cache read failed: %s", exc)
        return None
    if not row:
        return None
    try:
        payload = json.loads(row[0])
    except Exception:
        return None
    cached_at = int(row[1] or 0)
    age = int(time.time()) - cached_at
    if age > _ttl_for_payload(payload):
        return None
    return _reband_payload(payload)


def cache_put(url: str, payload: dict) -> None:
    """Store a prediction for `url`. Best-effort - failures are swallowed."""
    if not url or not payload:
        return
    conn = _cache_connection()
    if conn is None:
        return
    key = _normalize_cache_key(url)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO ml_cache(url_key, payload, cached_at) VALUES (?, ?, ?)",
            (key, json.dumps(payload), int(time.time())),
        )
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("ML cache write failed: %s", exc)


def cache_stats() -> dict:
    """For an /admin endpoint - rough cache size + age range."""
    conn = _cache_connection()
    if conn is None:
        return {"enabled": False}
    try:
        size = conn.execute("SELECT COUNT(*) FROM ml_cache").fetchone()[0]
        oldest = conn.execute("SELECT MIN(cached_at) FROM ml_cache").fetchone()[0]
        newest = conn.execute("SELECT MAX(cached_at) FROM ml_cache").fetchone()[0]
        return {
            "enabled": True,
            "entries": int(size or 0),
            "ttl_seconds_benign": _CACHE_TTL_BENIGN,
            "ttl_seconds_malicious": _CACHE_TTL_MALICIOUS,
            "oldest_age_seconds": int(time.time() - oldest) if oldest else None,
            "newest_age_seconds": int(time.time() - newest) if newest else None,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {"enabled": False, "error": str(exc)}


def cache_evict_expired() -> int:
    """Background cleanup - return number of rows removed.

    Walks rows and applies the per-bucket TTL. Cheaper than evicting on
    every read, and lets the SQLite file stay compact.
    """
    conn = _cache_connection()
    if conn is None:
        return 0
    cutoff_benign = int(time.time()) - _CACHE_TTL_BENIGN
    cutoff_mal = int(time.time()) - _CACHE_TTL_MALICIOUS
    # Conservatively delete anything older than the largest TTL when we
    # can't inspect the payload; the per-bucket pass handles the rest.
    try:
        # Per-bucket eviction: parse payload JSON for buckets we know.
        rows = conn.execute("SELECT url_key, payload, cached_at FROM ml_cache").fetchall()
    except Exception:
        return 0
    removed = 0
    for url_key, payload_json, cached_at in rows:
        try:
            payload = json.loads(payload_json)
        except Exception:
            payload = {}
        ttl_cutoff = cutoff_mal if (payload.get("bucket") in ("malicious", "suspicious", "uncertain")) else cutoff_benign
        if int(cached_at or 0) < ttl_cutoff:
            try:
                conn.execute("DELETE FROM ml_cache WHERE url_key = ?", (url_key,))
                removed += 1
            except Exception:
                continue
    return removed

