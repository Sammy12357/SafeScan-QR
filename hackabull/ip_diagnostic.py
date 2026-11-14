"""Temporary, owner-only ingress comparison without exposing client IPs.

Remove this module, its route, tests, and Render environment variables after
the two-device comparison on both public hostnames is complete.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os

from fastapi import Request


def diagnostic_key() -> str | None:
    """Require an explicit opt-in and a stable, non-default HMAC key."""
    if os.getenv("RENDER", "").strip().lower() != "true":
        return None
    if os.getenv("CLIENT_IP_DIAGNOSTIC_ENABLED", "").strip().lower() != "true":
        return None
    key = os.getenv("CLIENT_IP_DIAGNOSTIC_HMAC_KEY", "")
    return key if len(key.encode("utf-8")) >= 32 else None


def _canonical_ip(value: str | None) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    if value != value.strip() or "," in value or "%" in value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _fingerprint(ip: str | None, key: str) -> str | None:
    if ip is None:
        return None
    message = f"safescan-client-ip-diagnostic-v1:{ip}".encode("ascii")
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()[:32]


def diagnostic_snapshot(request: Request, resolved_ip: str | None, key: str) -> dict:
    """Expose only comparison fingerprints and header shape, never values."""
    edge_values = request.headers.getlist("cf-connecting-ip")
    edge_ip = _canonical_ip(edge_values[0]) if len(edge_values) == 1 else None
    resolved_ip = _canonical_ip(resolved_ip)
    edge_fingerprint = _fingerprint(edge_ip, key)
    resolved_fingerprint = _fingerprint(resolved_ip, key)
    return {
        "edgeHeaderPresent": bool(edge_values),
        "edgeHeaderSingle": len(edge_values) == 1,
        "edgeHeaderValid": edge_ip is not None,
        "resolvedIpValid": resolved_ip is not None,
        "edgeFingerprint": edge_fingerprint,
        "resolvedFingerprint": resolved_fingerprint,
        "fingerprintsMatch": (
            edge_fingerprint == resolved_fingerprint
            if edge_fingerprint and resolved_fingerprint else None
        ),
    }
