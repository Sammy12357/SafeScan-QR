"""Bounded, anonymous scanner counters. Never store or log individual events."""

from __future__ import annotations

import asyncio
from collections import deque
import json
import math
from threading import Lock
import time

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from .app_module import qr_app
from .config import SCANNER_CAPTURE_SECONDS, SCANNER_EVENTS, SCANNER_GUIDANCE


MAX_BODY_BYTES = 512
EVENT_LIMIT_PER_MINUTE = 300
ENGINES = frozenset({"wasm", "native+wasm", "unavailable"})
STAGES = frozenset({"capture", "server_retry"})
OUTCOMES = frozenset({"success", "no_code", "ambiguous", "decoder_error", "offered", "sent", "send_failed"})
GUIDANCE = frozenset({"multiple", "edge", "small", "blur", "dark", "glare", "tilt", "invalid", "none", "ready"})
REQUIRED_FIELDS = frozenset({"engine", "stage", "frames_tried", "ms", "outcome", "guidance_shown"})

# The global budget controls ingestion only. It contains timestamps, no IPs,
# session IDs, payloads, images, or request metadata, and expires in a minute.
_recent_events = deque()
_recent_events_lock = Lock()


def _valid_event(event):
    if not isinstance(event, dict) or set(event) != REQUIRED_FIELDS:
        return False
    if any(type(event[name]) is not str for name in ("engine", "stage", "outcome")):
        return False
    if event["engine"] not in ENGINES or event["stage"] not in STAGES or event["outcome"] not in OUTCOMES:
        return False
    frames = event["frames_tried"]
    duration = event["ms"]
    if type(frames) is not int or not 0 <= frames <= 8:
        return False
    if type(duration) not in (int, float) or not 0 <= duration <= 30_000 or not math.isfinite(duration):
        return False
    shown = event["guidance_shown"]
    return isinstance(shown, list) and len(shown) <= 20 and all(type(value) is str and value in GUIDANCE for value in shown)


def _admit_count():
    now = time.monotonic()
    with _recent_events_lock:
        while _recent_events and now - _recent_events[0] >= 60:
            _recent_events.popleft()
        if len(_recent_events) >= EVENT_LIMIT_PER_MINUTE:
            return False
        _recent_events.append(now)
    return True


@qr_app.post("/api/telemetry/scan", include_in_schema=False)
async def scanner_telemetry(request: Request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        return JSONResponse({"error": "Expected JSON."}, status_code=415)
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) < 0 or int(declared) > MAX_BODY_BYTES:
                return JSONResponse({"error": "Event is too large."}, status_code=413)
        except ValueError:
            return JSONResponse({"error": "Invalid content length."}, status_code=400)

    received = bytearray()
    try:
        async with asyncio.timeout(3):
            async for chunk in request.stream():
                received.extend(chunk)
                if len(received) > MAX_BODY_BYTES:
                    return JSONResponse({"error": "Event is too large."}, status_code=413)
    except TimeoutError:
        return JSONResponse({"error": "Event timed out."}, status_code=408)
    try:
        event = json.loads(received)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JSONResponse({"error": "Invalid event."}, status_code=400)
    if not _valid_event(event):
        return JSONResponse({"error": "Invalid event."}, status_code=400)
    if not _admit_count():
        return JSONResponse({"error": "Telemetry is busy."}, status_code=429, headers={"Retry-After": "60"})

    SCANNER_EVENTS.labels(engine=event["engine"], stage=event["stage"], outcome=event["outcome"]).inc()
    SCANNER_CAPTURE_SECONDS.labels(stage=event["stage"]).observe(event["ms"] / 1000)
    for category in event["guidance_shown"]:
        SCANNER_GUIDANCE.labels(category=category).inc()
    return Response(status_code=204)
