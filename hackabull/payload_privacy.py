"""Minimize what QR scans retain after an analysis response is returned.

Non-web QR payloads can contain TOTP seeds, Wi-Fi passwords, wallet pairing
keys, contact details, and arbitrary app secrets. Keep a keyed, per-user
fingerprint for scan counting, never the payload or a plain hash of it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets


_PROCESS_FINGERPRINT_KEY = secrets.token_bytes(32)
_REDACTED_SUFFIX = " QR payload redacted"


def is_web_url_payload(value: str, payload_type: str | None = None) -> bool:
    if payload_type:
        return payload_type == "URL"
    value = (value or "").strip()
    return bool(re.match(r"^https?://", value, re.IGNORECASE))


def is_redacted_scan_reference(value: str) -> bool:
    return bool(re.match(r"^\[[A-Za-z/ -]+ QR payload redacted(?:; ref [a-f0-9]{32})?\]$", value or ""))


def _payload_label(payload_type: str | None) -> str:
    label = re.sub(r"[^A-Za-z/ -]", "", payload_type or "Non-URL").strip()
    return label[:32] or "Non-URL"


def redacted_scan_label(payload_type: str | None = None) -> str:
    return f"[{_payload_label(payload_type)}{_REDACTED_SUFFIX}]"


def _fingerprint_key() -> bytes:
    for name in ("QR_PAYLOAD_FINGERPRINT_KEY", "AIRDROP_ADMIN_SECRET"):
        candidate = os.getenv(name, "").encode("utf-8")
        if len(candidate) >= 32:
            return candidate
    return _PROCESS_FINGERPRINT_KEY


def scan_storage_reference(raw_payload: str, owner: str = "", payload_type: str | None = None) -> str:
    """Return a useful deduplication key without retaining non-URL content.

    ``QR_PAYLOAD_FINGERPRINT_KEY`` should be set for stable deduplication over
    restarts. The existing admin secret is a stable fallback; otherwise a
    process-random key still protects the payload from offline guessing.
    """
    raw_payload = (raw_payload or "").strip()
    if is_redacted_scan_reference(raw_payload):
        return raw_payload
    if is_web_url_payload(raw_payload, payload_type):
        return raw_payload[:2048]
    message = b"safescan-private-qr-v1\0" + (owner or "").encode("utf-8") + b"\0" + raw_payload.encode("utf-8")
    fingerprint = hmac.new(_fingerprint_key(), message, hashlib.sha256).hexdigest()[:32]
    return f"[{_payload_label(payload_type)}{_REDACTED_SUFFIX}; ref {fingerprint}]"


def safe_legacy_scan_value(value: str, payload_type: str | None = None) -> str:
    """Hide pre-fix non-URL values in history and API serialization."""
    value = value or ""
    if is_redacted_scan_reference(value) or is_web_url_payload(value, payload_type):
        return value
    return redacted_scan_label(payload_type)


def private_history_signals(payload_type: str | None, score: int) -> list[dict[str, str]]:
    """A minimal history explanation that cannot contain attacker text."""
    return [{
        "label": f"{_payload_label(payload_type)} QR action",
        "severity": "high" if score >= 80 else "medium",
        "detail": "Payload details are withheld from scan history to protect private data.",
    }]
