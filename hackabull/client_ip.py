"""Resolve client identity only across a known ingress trust boundary.

Render's public web-service ingress overwrites CF-Connecting-IP. An arbitrary
X-Forwarded-For or True-Client-IP header is never evidence of client identity.
Requests sent directly to this app over Render's private network do not pass
through that ingress; private-network access must stay within trusted services.
"""

from __future__ import annotations

import ipaddress
import os

from fastapi import Request


def _canonical_ip(value: str | None) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    # An edge-authored value is exactly one IP literal, without ports, lists,
    # zone IDs, surrounding whitespace, or other client-controlled syntax.
    if value != value.strip() or "," in value or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def _socket_peer_ip(request: Request) -> str | None:
    return _canonical_ip(request.client.host if request.client else None)


def request_ip(request: Request) -> str | None:
    """Return a verified client IP, or None when ingress identity is missing.

    The Render branch is safe for public web-service requests because Render
    overwrites CF-Connecting-IP at its Cloudflare edge. Uvicorn must run with
    ``--no-proxy-headers`` so the fallback socket peer cannot be rewritten
    from an X-Forwarded-For header.
    """
    if os.getenv("RENDER", "").strip().lower() == "true":
        edge_values = request.headers.getlist("cf-connecting-ip")
        return _canonical_ip(edge_values[0]) if len(edge_values) == 1 else None
    return _socket_peer_ip(request)


def rate_limit_identity(request: Request) -> str:
    """Always return a limit key, including when Render's edge IP is absent.

    An invalid or missing edge header must not disable a rate limit. Those
    exceptional requests share a bucket by their actual socket peer instead
    of claiming an unverified client IP for fraud or audit records.
    """
    verified_ip = request_ip(request)
    if verified_ip is not None:
        return verified_ip
    peer = _socket_peer_ip(request) or "unknown"
    if os.getenv("RENDER", "").strip().lower() == "true":
        return f"unverified-ingress:{peer}"
    return f"unverified-socket:{peer}"
