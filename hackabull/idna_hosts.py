"""One IDNA 2008/UTS #46 host conversion for inspection and outbound fetches."""

from __future__ import annotations

import ipaddress

import idna


def canonical_ascii_host(hostname: str) -> str:
    host = (hostname or "").rstrip(".")
    if not host:
        raise idna.IDNAError("empty hostname")
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        return idna.encode(host, uts46=True, std3_rules=True).decode("ascii").lower()
