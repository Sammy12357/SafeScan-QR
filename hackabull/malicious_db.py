"""Public threat indicators approved by an administrator.

Personal scan history can contain password-reset links, access tokens and
other secrets in otherwise ordinary web URLs. It must never be a source for a
public feed, including through search, pagination or generated QR images.
"""

from __future__ import annotations

import hashlib
import ipaddress
import sqlite3
from urllib.parse import urlsplit

import tldextract

from db import get_conn
from .idna_hosts import canonical_ascii_host


_EXTRACT_DOMAIN = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=False, include_psl_private_domains=True
)


def _public_domain(value: str) -> str:
    """Return only a broad DNS indicator from an admin-confirmed web URL."""
    try:
        parsed = urlsplit((value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"}:
            return ""
        host = canonical_ascii_host(parsed.hostname or "")
        if not host or len(host) > 253 or any(len(label) > 63 for label in host.split(".")):
            return ""
        if not all(label and label[0].isalnum() and label[-1].isalnum() and
                   all(char.isalnum() or char == "-" for char in label)
                   for label in host.split(".")):
            return ""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            return ""  # Never publish local, private or user-specific IPs.
        if "." not in host:
            return ""
        extracted = _EXTRACT_DOMAIN(host)
        if not extracted.domain or not extracted.suffix or extracted.is_private:
            return ""  # Unknown/internal suffixes and shared hosting are not public indicators.
        domain = f"{extracted.domain}.{extracted.suffix}"
        if host != domain:
            return ""  # A bad tenant/subdomain does not implicate the parent domain.
        return domain
    except (UnicodeError, ValueError):
        return ""


def get_malicious_qr_codes(page: int = 1, limit: int = 20, query: str = "") -> dict:
    """List sanitized domains from active, admin-confirmed URL blocklist rows.

    Search only the published domain, so private URL paths and tokens cannot
    be probed by asking whether a particular query matches a hidden row.
    """
    page = max(1, int(page or 1))
    limit = max(1, min(int(limit or 20), 100))
    search = (query or "").strip().lower()[:200]
    domains: dict[str, dict] = {}

    with get_conn() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT url, created_at FROM url_blocklist WHERE removed_at IS NULL ORDER BY created_at DESC"
        )
        for row in rows:
            domain = _public_domain(row["url"])
            if not domain:
                continue
            entry = domains.setdefault(domain, {
                "id": hashlib.sha256(domain.encode("ascii")).hexdigest()[:16],
                "domain": domain,
                "category": "Admin confirmed",
                "lastReportedAt": row["created_at"],
                "reports": 0,
            })
            entry["reports"] += 1
            if row["created_at"] > entry["lastReportedAt"]:
                entry["lastReportedAt"] = row["created_at"]

    ordered = sorted(domains.values(), key=lambda entry: (entry["lastReportedAt"], entry["domain"]), reverse=True)
    total_reports = sum(entry["reports"] for entry in ordered)
    last_updated = ordered[0]["lastReportedAt"] if ordered else None
    if search:
        ordered = [entry for entry in ordered if search in entry["domain"]]
    total = len(ordered)
    start = (page - 1) * limit
    return {
        "entries": ordered[start:start + limit],
        "total": total,
        "page": page,
        "limit": limit,
        "totalPages": max(1, (total + limit - 1) // limit),
        "stats": {
            "totalDomains": len(domains),
            "totalReports": total_reports,
            "lastUpdated": last_updated,
        },
    }
