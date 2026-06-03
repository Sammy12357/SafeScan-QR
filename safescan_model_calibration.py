"""
Inference-time calibration + caching on top of the existing URL classifier
and CNN. These improvements ship without retraining.

What this fixes
---------------
1. **Threshold mismatch with training.**
   The notebook (`SafeScanQR_Improved`) found F1-optimal threshold = 0.32 on
   the validation set, but `ml_model_final.predict_url` and downstream code
   in `hackabull.classify_qr_with_ml` still split benign vs malicious at 0.5
   (and bucket as "Malicious" only at >= 80% probability). The result is a
   model that's far more conservative in production than it was during
   evaluation, weakening the malicious recall.

2. **No reject option for borderline scores.**
   When the classifier returns a probability between (say) 0.35 and 0.65
   it doesn't really *know* — the char-ngram model is not calibrated and
   close-to-50% scores carry near-zero information. Today we blend them
   into the final score anyway, polluting borderline calls. The
   `interpret_probability` function returns an `uncertain` band that
   `hackabull.classify_qr_with_ml` uses to suppress the ML signal entirely.

3. **No feature awareness for things the char-ngram model can't see.**
   The URL classifier is char-substring frequencies. It misses domain age,
   TLD reputation tier, hyphen-heavy hostnames, numeric-suffix branding,
   and basic brand-impersonation patterns. `lexical_feature_bonus` adds a
   small, capped post-hoc nudge to the malicious probability when those
   signals fire.

4. **No prediction caching.**
   Same URL scanned five times in a day re-runs the full pipeline
   five times. `prediction_cache` is a tiny SQLite-backed cache keyed on
   the normalized URL with a configurable TTL (default 1 hour).

None of these changes require retraining. They are intentionally
conservative - any one of them can be disabled via env var without
affecting the rest.
"""

from __future__ import annotations

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


# -----------------------------------------------------------------------------
# 1. Calibrated thresholding + uncertain band
# -----------------------------------------------------------------------------

# F1-optimal threshold from the training notebook's threshold sweep on val.
MALICIOUS_THRESHOLD = float(os.getenv("SAFESCAN_ML_MAL_THRESHOLD", "0.32"))

# The uncertain band brackets the malicious threshold. Probabilities inside
# this band are explicitly NOT trusted as signal; the analyzer will fall
# back to its rule pipeline + reputation checks instead of letting the ML
# nudge the final score. Defaults give a wide ~30 percentage-point band.
UNCERTAIN_LOWER = float(os.getenv("SAFESCAN_ML_UNCERTAIN_LOWER", "0.20"))
UNCERTAIN_UPPER = float(os.getenv("SAFESCAN_ML_UNCERTAIN_UPPER", "0.50"))

# The "confidently malicious" cutoff is intentionally raised above the
# notebook's 0.80 default. Above ~92% the classifier earns full credit;
# 0.50-0.92 still carries information but at reduced weight.
CONFIDENT_MALICIOUS_THRESHOLD = float(os.getenv("SAFESCAN_ML_CONFIDENT", "0.90"))


@dataclass
class CalibratedDecision:
    """Result of interpreting a raw ML malicious probability."""
    bucket: str          # one of: "benign", "uncertain", "suspicious", "malicious"
    severity: str        # one of: "low", "medium", "high"
    passed: bool         # True iff the URL is in the safe bucket
    trust_signal: bool   # True iff the ML signal should be exposed at all
    label: str           # short label for the signal UI


def interpret_probability(mal_probability: float) -> CalibratedDecision:
    """Map a raw 0..1 malicious probability into a stable analyzer decision.

    The bands are:
        [0, UNCERTAIN_LOWER)          -> benign     (low severity, trusted)
        [UNCERTAIN_LOWER, UPPER)      -> uncertain  (suppressed - no signal)
        [UPPER, CONFIDENT_MALICIOUS)  -> suspicious (medium, trusted)
        [CONFIDENT_MALICIOUS, 1.0]    -> malicious  (high, trusted)

    The uncertain band is the key change versus the notebook code: instead
    of forcing a binary call on a 50/50 score, we explicitly say "no useful
    signal" and let the deterministic rule pipeline + reputation checks
    decide.
    """
    p = max(0.0, min(1.0, float(mal_probability or 0.0)))

    if p < UNCERTAIN_LOWER:
        return CalibratedDecision("benign", "low", True, True, "Benign (ML)")
    if p < UNCERTAIN_UPPER:
        return CalibratedDecision("uncertain", "low", False, False, "Uncertain (ML)")
    if p < CONFIDENT_MALICIOUS_THRESHOLD:
        return CalibratedDecision("suspicious", "medium", False, True, "Suspicious (ML)")
    return CalibratedDecision("malicious", "high", False, True, "Malicious (ML)")


# -----------------------------------------------------------------------------
# 2. Lexical feature bonus
# -----------------------------------------------------------------------------

# TLDs frequently used in short-lived phishing campaigns. Public lists from
# Spamhaus, Cisco Talos, and Cofense converge on roughly this set.
HIGH_RISK_TLDS = frozenset({
    "zip", "mov", "click", "country", "kim", "loan", "party", "quest",
    "rest", "top", "work", "xyz", "tk", "ml", "ga", "cf", "gq",
    "icu", "buzz", "info", "link",
})

# Brand names commonly imitated by phishing kits. If the name appears in the
# hostname without matching the legitimate registrable domain, we add a
# malicious-probability bonus.
SENSITIVE_BRANDS = {
    "apple":     {"apple.com", "icloud.com"},
    "google":    {"google.com", "gmail.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "paypal":    {"paypal.com"},
    "coinbase":  {"coinbase.com"},
    "binance":   {"binance.com"},
    "phantom":   {"phantom.app"},
    "metamask":  {"metamask.io"},
    "solana":    {"solana.com", "solanafoundation.org"},
    "discord":   {"discord.com", "discord.gg"},
}


def _registrable_domain(host: str) -> str:
    host = (host or "").lower().lstrip("www.").strip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def lexical_feature_bonus(url: str) -> tuple[float, list[str]]:
    """Return (bonus, reasons) where bonus is a delta to add to the malicious
    probability and reasons lists which features fired.

    Bonus is clamped to [0, 0.20] - even when every feature fires, the
    bonus alone cannot push a benign score above the uncertain band on its
    own. It's meant to nudge already-suspicious scores upward, not invent
    risk from clean URLs.
    """
    reasons: list[str] = []
    if not url:
        return 0.0, reasons

    try:
        parsed = urlparse(url)
    except ValueError:
        return 0.0, reasons

    host = (parsed.hostname or "").lower()
    if not host:
        return 0.0, reasons

    domain = _registrable_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    bonus = 0.0

    if tld in HIGH_RISK_TLDS:
        bonus += 0.10
        reasons.append(f".{tld} high-risk TLD")

    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        bonus += 0.05
        reasons.append(f"{hyphen_count} hyphens in hostname")

    if re.search(r"\d{3,}", host):
        bonus += 0.04
        reasons.append("long digit run in hostname")

    subdomain_depth = max(0, host.count(".") - 1)
    if subdomain_depth >= 3:
        bonus += 0.04
        reasons.append(f"{subdomain_depth + 1} subdomain labels")

    # Brand impersonation: the brand name appears in the host but the host
    # is NOT under any of its legitimate registrable domains.
    compact_host = re.sub(r"[^a-z0-9]", "", host)
    for brand, legit_domains in SENSITIVE_BRANDS.items():
        if brand in compact_host and not any(
            domain == legit or host.endswith("." + legit) for legit in legit_domains
        ):
            bonus += 0.08
            reasons.append(f"{brand} brand in unrelated domain")
            break

    return min(bonus, 0.20), reasons


# -----------------------------------------------------------------------------
# 3. URL prediction cache (SQLite, TTL-based)
# -----------------------------------------------------------------------------

_CACHE_TTL_SECONDS = int(os.getenv("SAFESCAN_ML_CACHE_TTL", str(60 * 60)))
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
    """Case-fold + trim trailing slash so trivial URL variants share a row."""
    return (url or "").strip().lower().rstrip("/")


def cache_get(url: str) -> Optional[dict]:
    """Return the cached prediction for `url`, or None if absent or expired."""
    if not url:
        return None
    conn = _cache_connection()
    if conn is None:
        return None
    key = _normalize_cache_key(url)
    cutoff = int(time.time()) - _CACHE_TTL_SECONDS
    try:
        row = conn.execute(
            "SELECT payload FROM ml_cache WHERE url_key = ? AND cached_at >= ?",
            (key, cutoff),
        ).fetchone()
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("ML cache read failed: %s", exc)
        return None
    if not row:
        return None
    try:
        return json.loads(row[0])
    except Exception:
        return None


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
            "ttl_seconds": _CACHE_TTL_SECONDS,
            "oldest_age_seconds": int(time.time() - oldest) if oldest else None,
            "newest_age_seconds": int(time.time() - newest) if newest else None,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {"enabled": False, "error": str(exc)}


def cache_evict_expired() -> int:
    """Background cleanup - return number of rows removed."""
    conn = _cache_connection()
    if conn is None:
        return 0
    cutoff = int(time.time()) - _CACHE_TTL_SECONDS
    try:
        cur = conn.execute("DELETE FROM ml_cache WHERE cached_at < ?", (cutoff,))
        return cur.rowcount or 0
    except Exception:
        return 0
