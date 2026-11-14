"""Server-side verification of public form challenges with Cloudflare Turnstile."""

from __future__ import annotations

import asyncio
import json
import time

import requests
from fastapi import Request

from .audit import SafeScanError
from .config import TURNSTILE_ENABLED
from .config import TURNSTILE_HOSTNAMES
from .config import TURNSTILE_SECRET_KEY
from .config import TURNSTILE_SITE_KEY


SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
ALLOWED_ACTIONS = frozenset({"url_report", "data_request", "waitlist"})


def _siteverify(token: str) -> dict:
    # Cloudflare's remoteip parameter is optional. Do not send visitor IPs
    # to this provider merely to validate a challenge.
    deadline = time.monotonic() + 8
    with requests.post(
        SITEVERIFY_URL,
        data={"secret": TURNSTILE_SECRET_KEY, "response": token},
        timeout=(2, 3),
        allow_redirects=False,
        stream=True,
    ) as response:
        if response.status_code != 200:
            raise ValueError("Turnstile validation service returned an error")
        raw = bytearray()
        for chunk in response.iter_content(chunk_size=4096):
            # A read timeout applies to each socket read; a trickle of bytes
            # must not occupy a worker thread for an unbounded total time.
            if time.monotonic() >= deadline:
                raise ValueError("Turnstile validation service timed out")
            raw.extend(chunk)
            if len(raw) > 8192:
                raise ValueError("Turnstile validation response is too large")
        if time.monotonic() >= deadline:
            raise ValueError("Turnstile validation service timed out")
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Turnstile validation response is invalid")
        return parsed


async def verify_turnstile(request: Request, token: str | None, *, action: str) -> None:
    """Require an action- and hostname-bound, single-use token when enabled.

    Call only after local shape validation and rate limiting, before any
    expensive analysis, email delivery, or database mutation.
    """
    if not TURNSTILE_ENABLED:
        return
    host = (request.url.hostname or "").lower().rstrip(".")
    if (
        not TURNSTILE_SITE_KEY or not TURNSTILE_SECRET_KEY or not TURNSTILE_HOSTNAMES
        or host not in TURNSTILE_HOSTNAMES or action not in ALLOWED_ACTIONS
    ):
        raise SafeScanError("Security verification is temporarily unavailable.", 503)
    if not isinstance(token, str) or not (1 <= len(token) <= 2048):
        raise SafeScanError("Complete the security verification and try again.", 400)
    try:
        result = await asyncio.to_thread(_siteverify, token)
    except (requests.RequestException, ValueError):
        raise SafeScanError("Security verification is temporarily unavailable.", 503) from None
    if (
        result.get("success") is not True
        or result.get("hostname") != host
        or result.get("action") != action
    ):
        raise SafeScanError("Complete the security verification and try again.", 400)
