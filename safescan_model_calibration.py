"""
Inference-time calibration + caching on top of the existing URL classifier
and CNN. These improvements ship without retraining.

What this fixes
---------------
1. **Threshold mismatch with training.**
   The notebook (`SafeScanQR_Improved`) found F1-optimal threshold = 0.32 on
   the validation set, but `ml_model_final.predict_url` and downstream code
   in `hackabull.classify_qr_with_ml` previously split benign vs malicious
   at 0.5 (and bucketed as "Malicious" only at >= 80% probability). The
   result was a model more conservative in production than in evaluation,
   weakening malicious recall.

2. **No reject option for borderline scores.**
   When the classifier returns a probability between (say) 0.35 and 0.65 it
   doesn't really *know* - the char-ngram model is not calibrated and
   close-to-50% scores carry near-zero information. `interpret_probability`
   returns an `uncertain` band that `hackabull.classify_qr_with_ml` uses to
   suppress the ML signal entirely.

3. **No feature awareness for things the char-ngram model can't see.**
   The URL classifier is char-substring frequencies. It misses domain age,
   TLD reputation tier, raw-IP hosts, userinfo obfuscation, punycode,
   hyphen-heavy hostnames, brand impersonation, and off-brand sensitive
   keywords. `lexical_feature_bonus` adds a small, capped post-hoc nudge.

4. **No prediction caching.**
   Same URL scanned five times in a day re-runs the full pipeline. The
   cache is keyed on the normalized URL (matching the classifier's own
   normalization so HTTP/HTTPS variants share a row) with split TTLs:
   benign verdicts live longer, malicious/suspicious verdicts expire fast
   so takedowns are seen quickly. Raw probability is stored alongside the
   payload so calibration tweaks don't require flushing the cache.

None of these changes require retraining. They are intentionally
conservative - any one of them can be disabled via env var without
affecting the rest.
"""

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


# -----------------------------------------------------------------------------
# 1. Calibrated thresholding + uncertain band
# -----------------------------------------------------------------------------

# F1-optimal threshold from the training notebook's threshold sweep on val.
# Used by ml_model_final._result_from_probs to label raw classifier output.
MALICIOUS_THRESHOLD = float(os.getenv("SAFESCAN_ML_MAL_THRESHOLD", "0.32"))

# The uncertain band brackets the malicious threshold. Probabilities inside
# this band are explicitly NOT trusted as signal; the analyzer falls back to
# its rule pipeline + reputation checks instead of letting the ML nudge the
# final score. Defaults give a ~30 percentage-point band.
UNCERTAIN_LOWER = float(os.getenv("SAFESCAN_ML_UNCERTAIN_LOWER", "0.20"))
UNCERTAIN_UPPER = float(os.getenv("SAFESCAN_ML_UNCERTAIN_UPPER", "0.50"))

# The "confidently malicious" cutoff is intentionally raised above the
# notebook's 0.80 default. Above ~90% the classifier earns full credit;
# 0.50-0.90 still carries information but at reduced weight.
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
# Spamhaus, Cisco Talos, and Cofense converge on roughly this set. Note: we
# intentionally exclude .info and .link - both have far too much legitimate
# use to justify a 10-point bonus on top of the classifier score.
HIGH_RISK_TLDS = frozenset({
    "zip", "mov", "click", "country", "kim", "loan", "party", "quest",
    "rest", "top", "work", "xyz", "tk", "ml", "ga", "cf", "gq",
    "icu", "buzz",
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

# Path/query keywords that look benign on a brand site but suspicious on a
# random hyphenated burner domain.
SENSITIVE_KEYWORDS = (
    "login", "signin", "verify", "verification", "secure", "account",
    "wallet", "seed", "recovery", "airdrop", "mint", "claim", "unlock",
    "support", "validate", "confirm",
)

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+\-.]*://", re.IGNORECASE)


def _normalize_url(url: str) -> str:
    """Match ml_model_final._normalize_url - strip scheme, lowercase, no slash.

    Mirrored here so we don't import ml_model_final at calibration import
    time (TF/Keras import is heavy and slow). Kept in lock-step so the
    cache key and the classifier input agree.
    """
    url = (url or "").strip()
    url = _SCHEME_RE.sub("", url, count=1)
    return url.lower().rstrip("/")


def _registrable_domain(host: str) -> str:
    """Return host's registrable domain using the public suffix list.

    Falls back to a naive last-two-labels split if tldextract is not
    importable. The naive path also uses removeprefix - the previous
    lstrip("www.") was a character-set strip, which silently mangled hosts
    like "wikipedia.org" (-> "ikipedia.org") and "www2.foo.com".
    """
    host = (host or "").lower().removeprefix("www.").strip(".")
    if not host:
        return ""
    try:
        import tldextract
        extracted = tldextract.extract(host)
        registrable = ".".join(part for part in (extracted.domain, extracted.suffix) if part)
        return registrable or host
    except Exception:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def lexical_feature_bonus(url: str) -> tuple[float, list[str]]:
    """Return (bonus, reasons) where bonus is a delta to add to the malicious
    probability and reasons lists which features fired.

    Bonus is clamped to [0, 0.20] - even when every feature fires, the
    bonus alone cannot push a benign score above the uncertain band on its
    own. Meant to nudge already-suspicious scores upward, not invent risk
    from clean URLs.
    """
    reasons: list[str] = []
    if not url:
        return 0.0, reasons

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except ValueError:
        return 0.0, reasons

    host = (parsed.hostname or "").lower()
    if not host:
        return 0.0, reasons

    domain = _registrable_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    bonus = 0.0

    # --- Host shape signals ------------------------------------------------

    if _is_ip_host(host):
        bonus += 0.12
        reasons.append("raw IP host")
    elif tld in HIGH_RISK_TLDS:
        bonus += 0.10
        reasons.append(f".{tld} high-risk TLD")

    if host.startswith("xn--") or ".xn--" in host:
        bonus += 0.06
        reasons.append("punycode host (possible homoglyph)")

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

    # --- URL shape signals -------------------------------------------------

    # Userinfo (user:pass@host) is the textbook obfuscation trick - it lets
    # the displayed host disagree with the resolved host.
    if "@" in (parsed.netloc or "") and not _is_ip_host(host):
        bonus += 0.08
        reasons.append("userinfo in URL")

    # Non-standard ports on a non-local host are unusual for legitimate
    # consumer-facing services; common in malware C2 and quick stand-ups.
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port and port not in (80, 443) and not _is_ip_host(host):
        bonus += 0.04
        reasons.append(f"non-standard port :{port}")

    if len(url) >= 200:
        bonus += 0.03
        reasons.append("very long URL")

    # Plain http to a public host (not localhost / RFC1918) is increasingly
    # rare for genuine destinations - browsers warn on it.
    if (parsed.scheme or "").lower() == "http" and host not in ("localhost",) and not _is_ip_host(host):
        bonus += 0.02
        reasons.append("plain http (no TLS)")

    # --- Brand impersonation ----------------------------------------------
    #
    # Accumulate across brands - "coinbase-binance-login.tk" should pay for
    # both brand hits, not just the first one found. Cap per-URL is enforced
    # below by min(bonus, 0.20).
    compact_host = re.sub(r"[^a-z0-9]", "", host)
    impersonated: list[str] = []
    for brand, legit_domains in SENSITIVE_BRANDS.items():
        if brand in compact_host and not any(
            domain == legit or host.endswith("." + legit) for legit in legit_domains
        ):
            impersonated.append(brand)
    for brand in impersonated:
        bonus += 0.08
        reasons.append(f"{brand} brand in unrelated domain")

    # --- Sensitive keywords on an off-brand host --------------------------
    #
    # "login" on apple.com is fine; "login" on apple-secure-1234.tk is not.
    # We only count this when the host is NOT on a legit brand domain (i.e.
    # at least one impersonation match was found OR the TLD is high-risk).
    full_url_lower = url.lower()
    if impersonated or tld in HIGH_RISK_TLDS or _is_ip_host(host):
        hits = [k for k in SENSITIVE_KEYWORDS if k in full_url_lower]
        if hits:
            bonus += 0.03
            reasons.append(f"sensitive keywords on risky host ({', '.join(hits[:3])})")

    return min(bonus, 0.20), reasons


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
