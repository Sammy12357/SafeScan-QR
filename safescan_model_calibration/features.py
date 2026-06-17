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


