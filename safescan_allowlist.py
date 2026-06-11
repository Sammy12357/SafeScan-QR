"""
Tranco top-N domain allowlist short-circuit.

Why this exists
---------------
The full analyzer pipeline (`analyze_full_pipeline` in hackabull.py) runs an
EfficientNet QR image classifier, an LLM verdict generator, a VirusTotal
lookup, redirect tracing, and Google Safe Browsing in parallel for every
single URL. That's 5-10 seconds plus paid API spend on every scan.

For QR codes that point at the long tail of mainstream websites (Google,
YouTube, Apple, GitHub, Wikipedia, etc.) the ML+LLM stages add zero signal
- those domains are obviously fine. We can short-circuit them with a small
allowlist lookup and only run the cheap reputation checks (Google Safe
Browsing) before returning a SAFE verdict.

What this is NOT
----------------
This is NOT a "trust everything from popular domains" rubber stamp. The
short-circuit only fires when ALL of these are true:

  1. The URL's registrable domain (eTLD+1) is in the Tranco top N.
  2. A `safety_screen` check passes (HTTPS, no @, no raw IP, no punycode,
     no shortener, no executable scheme, no homograph-prone characters).
  3. The URL does NOT contain a redirect-style query parameter (?url=,
     ?redirect=, ?next=, ?continue=, ?goto=) - those are abused for
     phishing on otherwise-legit sites.

If any of those fail, the URL falls through to the full pipeline. Google
Safe Browsing is ALSO consulted on the fast path so a compromised popular
site flagged by Google still gets caught.

How to update the list
----------------------
1. Download a fresh Tranco list: https://tranco-list.eu/
2. Extract the top 10K into `data/tranco_top_10k.csv`
   (format: `<rank>,<domain>` per line, no header)
3. Redeploy. The set is loaded into memory at startup.

Refresh weekly is reasonable - the top 10K barely changes day to day.
"""

from __future__ import annotations

import csv
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

LOG = logging.getLogger(__name__)

# The app's own canonical URL. Mirrors the APP_URL default in hackabull.py.
DEFAULT_APP_URL = "https://safescan-qr.onrender.com"

# Path is resolved relative to this file so it works regardless of cwd.
ALLOWLIST_FILE = Path(__file__).resolve().parent / "data" / "tranco_top_10k.csv"

# Hosts that are popular AND inherently anonymous redirects - never short-
# circuit these even if they're in the top 10K. They hide their final
# destination by design, which defeats the purpose of an allowlist check.
SHORTENER_HOSTS = frozenset({
    "bit.ly", "cutt.ly", "goo.gl", "is.gd", "lnkd.in", "ow.ly",
    "rebrand.ly", "shorturl.at", "t.co", "tiny.cc", "tinyurl.com",
    "trib.al", "rb.gy", "buff.ly", "shorte.st",
})

# Query parameter names that frequently indicate an open redirect chain
# on legit sites (e.g. google.com/url?q=, facebook.com/l.php?u=).
REDIRECT_PARAM_NAMES = frozenset({
    "url", "redirect", "redirect_uri", "redirecturl", "redirect_url",
    "next", "continue", "goto", "dest", "destination", "return",
    "returnurl", "return_url", "u", "q",
})

# Multi-tenant hosting / PaaS domains where the registrable domain (eTLD+1)
# is itself shared infrastructure - anyone can stand up
# `phisher.github.io`, `scam-site.vercel.app`, etc. Treating these as
# "Tranco top N = popular = safe" would let third-party phishing pages
# hosted on legit platforms bypass the full pipeline. Only the bare apex
# domain (no subdomain) counts as the allowlisted entry; any subdomain
# must go through the full analysis.
MULTI_TENANT_SUFFIXES = frozenset({
    "github.io", "githubusercontent.com", "gitlab.io",
    "vercel.app", "netlify.app", "web.app", "firebaseapp.com",
    "herokuapp.com", "pages.dev", "appspot.com", "azurewebsites.net",
    "wixsite.com", "weebly.com", "blogspot.com", "wordpress.com",
    "workers.dev", "googleusercontent.com", "amazonaws.com",
    "s3.amazonaws.com", "glitch.me", "repl.co", "surge.sh",
    "000webhostapp.com", "myshopify.com", "square.site",
    "render.com", "onrender.com", "fly.dev", "ngrok.io", "ngrok-free.app",
})

# Common ccTLD suffixes where the registrable domain is 3 labels deep
# (foo.co.uk, foo.com.au, etc.) rather than 2. Not exhaustive but covers
# the cases that matter for an allowlist match against Tranco's 2-label
# entries.
TWO_LABEL_PUBLIC_SUFFIXES = frozenset({
    "co.uk", "ac.uk", "gov.uk", "org.uk",
    "co.jp", "ne.jp", "or.jp",
    "co.kr",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "com.mx", "com.ar", "com.tr",
    "co.in", "co.za", "co.nz", "com.py",
})

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Cyrillic / Greek characters that look identical to Latin letters and are
# the basis of most homograph attacks. Allowing a hostname through that
# contains one of these would defeat the safety screen.
HOMOGRAPH_CHARS_RE = re.compile(r"[Ѐ-ӿͰ-Ͽ]")


def _strip_port(host: str) -> str:
    return host.split(":", 1)[0]


def registrable_domain(host: str) -> str:
    """
    Return the eTLD+1 for a hostname using a small built-in suffix list.

    Examples:
        accounts.google.com -> google.com
        www.bbc.co.uk       -> bbc.co.uk
        cdn.shopify.com     -> shopify.com
    """
    host = _strip_port(host or "").lower().strip(".")
    if not host:
        return ""
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in TWO_LABEL_PUBLIC_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


@lru_cache(maxsize=1)
def load_allowlist() -> frozenset[str]:
    """Read tranco_top_10k.csv on first call, cache forever."""
    if not ALLOWLIST_FILE.exists():
        LOG.warning("Tranco allowlist file missing at %s; short-circuit disabled.", ALLOWLIST_FILE)
        return frozenset()

    domains: set[str] = set()
    with ALLOWLIST_FILE.open("r", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        for row in reader:
            if len(row) >= 2:
                domain = row[1].strip().lower()
                if domain:
                    domains.add(domain)

    LOG.info("Tranco allowlist loaded: %d domains", len(domains))
    return frozenset(domains)


def is_known_popular(host: str) -> bool:
    """True iff the host's registrable domain is in the Tranco set.

    For multi-tenant hosting domains (see MULTI_TENANT_SUFFIXES), only the
    bare apex domain qualifies - any subdomain is independently controlled
    by a third party and must go through the full pipeline.
    """
    domain = registrable_domain(host)
    if not domain or domain not in load_allowlist():
        return False
    if domain in MULTI_TENANT_SUFFIXES:
        normalized_host = _strip_port((host or "").lower().strip("."))
        if normalized_host.startswith("www."):
            normalized_host = normalized_host[4:]
        return normalized_host == domain
    return True


def safety_screen(url: str) -> tuple[bool, str]:
    """
    Cheap structural URL checks that must pass for any short-circuit.

    Returns (ok, reason). When ok is False, reason is a human-readable
    explanation suitable for the audit log; the caller should fall back to
    the full pipeline.
    """
    if not url or not isinstance(url, str):
        return False, "empty url"

    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "unparseable url"

    if parsed.scheme.lower() != "https":
        return False, f"non-https scheme: {parsed.scheme!r}"

    if "@" in (parsed.netloc or ""):
        return False, "@ in netloc (URL deception)"

    host = _strip_port((parsed.hostname or "").lower())
    if not host:
        return False, "empty host"

    if IPV4_RE.match(host):
        return False, "raw IP host"

    if "xn--" in host:
        return False, "punycode host"

    if HOMOGRAPH_CHARS_RE.search(host):
        return False, "homograph-prone characters in host"

    domain = registrable_domain(host)
    if host in SHORTENER_HOSTS or domain in SHORTENER_HOSTS:
        return False, f"known URL shortener: {host}"

    # Open-redirect-style query params on a "trusted" domain are the most
    # common abuse vector for popular sites - treat their presence as a
    # short-circuit blocker so the full pipeline can trace where they go.
    query_keys = {key.lower() for key in _query_keys(parsed.query)}
    abused = query_keys & REDIRECT_PARAM_NAMES
    if abused:
        return False, f"redirect-style query param: {sorted(abused)}"

    return True, "ok"


def _query_keys(raw_query: str) -> list[str]:
    """urllib.parse_qs is fussy about malformed inputs; do it by hand."""
    if not raw_query:
        return []
    pairs = raw_query.split("&")
    return [p.split("=", 1)[0] for p in pairs if p]


@lru_cache(maxsize=1)
def first_party_hosts() -> frozenset[str]:
    """Hostnames that belong to this SafeScan deployment itself.

    Built from APP_URL plus the optional SAFESCAN_TRUSTED_HOSTS env var
    (comma-separated hostnames, e.g. a custom domain in front of Render).
    The production host is always included so QR codes pointing at the
    live site stay first-party even when APP_URL targets a preview deploy.
    """
    hosts: set[str] = set()
    for candidate_url in (os.getenv("APP_URL", "").strip(), DEFAULT_APP_URL):
        host = (urlparse(candidate_url).hostname or "").lower().strip(".")
        if host:
            hosts.add(host)
    for raw in os.getenv("SAFESCAN_TRUSTED_HOSTS", "").split(","):
        extra = raw.strip().lower().strip(".")
        if extra:
            hosts.add(extra)
    return frozenset(hosts)


def is_first_party(url: str) -> bool:
    """True iff the URL points at this SafeScan deployment itself.

    SafeScan generates QR codes that link back to its own pages (the
    generator, shared scan results, referral links). Running the ML
    pipeline against those is circular and misfires because onrender.com
    is multi-tenant hosting, so the analyzer treats its own domain as a
    deterministic SAFE verdict instead.

    Exact hostname match only - no subdomain or suffix matching - so
    `safescan-qr.onrender.com.evil.test` and `evil-safescan-qr.onrender.com`
    never qualify. Userinfo deception (`https://x@host/`) is rejected even
    when the real destination is ours, because a legitimate first-party QR
    code never carries credentials in the URL.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if "@" in (parsed.netloc or ""):
        return False
    host = _strip_port((parsed.hostname or "").lower()).strip(".")
    return bool(host) and host in first_party_hosts()


def should_short_circuit(url: str) -> tuple[bool, str]:
    """
    Decide whether the analyzer can skip the ML / LLM / VirusTotal stages
    for this URL. Caller should still run Google Safe Browsing on the
    fast path - this short-circuit does NOT guarantee safety on its own.

    Returns (ok, reason). When ok is False, reason explains why we fell
    through; useful for telemetry on hit rate.
    """
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False, "unparseable url"

    if not is_known_popular(host):
        return False, "domain not in Tranco top N"

    screen_ok, reason = safety_screen(url)
    if not screen_ok:
        return False, f"safety screen failed: {reason}"

    return True, "ok"
