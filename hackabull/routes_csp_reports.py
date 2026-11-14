"""Bounded, count-only receiver for opt-in report-only CSP measurements.

Browsers may include full URLs, query strings and source samples in reports.
None of those fields are logged, retained, or used as metric labels.
"""

from __future__ import annotations

import asyncio
from collections import deque
import json
from threading import Lock
import time

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from .app_module import qr_app
from .config import CSP_REPORT_ONLY_ENABLED, CSP_REPORTS


MAX_BODY_BYTES = 8 * 1024
MAX_REPORTS_PER_REQUEST = 16
REPORT_LIMIT_PER_MINUTE = 300
DIRECTIVE_BUCKETS = frozenset({"style-src", "style-src-attr", "style-src-elem"})
_recent_reports = deque()
_recent_reports_lock = Lock()


def _directives(payload, media_type: str) -> list[str] | None:
    if media_type == "application/csp-report":
        if not isinstance(payload, dict) or set(payload) != {"csp-report"}:
            return None
        report = payload["csp-report"]
        if not isinstance(report, dict):
            return None
        raw = report.get("effective-directive") or report.get("violated-directive")
        return [raw] if isinstance(raw, str) and raw else None

    if not isinstance(payload, list) or not 1 <= len(payload) <= MAX_REPORTS_PER_REQUEST:
        return None
    directives = []
    for report in payload:
        if not isinstance(report, dict) or report.get("type") != "csp-violation":
            return None
        body = report.get("body")
        if not isinstance(body, dict):
            return None
        raw = body.get("effectiveDirective")
        if not isinstance(raw, str) or not raw:
            return None
        directives.append(raw)
    return directives


def _admit_count(count: int) -> bool:
    now = time.monotonic()
    with _recent_reports_lock:
        while _recent_reports and now - _recent_reports[0] >= 60:
            _recent_reports.popleft()
        if len(_recent_reports) + count > REPORT_LIMIT_PER_MINUTE:
            return False
        _recent_reports.extend([now] * count)
    return True


@qr_app.post("/api/security/csp-report", include_in_schema=False)
async def csp_report(request: Request):
    if not CSP_REPORT_ONLY_ENABLED:
        return Response(status_code=404)

    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type not in {"application/csp-report", "application/reports+json"}:
        return JSONResponse({"error": "Unsupported report type."}, status_code=415)

    declared = request.headers.get("content-length")
    if declared is not None:
        if len(declared) > 8 or not declared.isdecimal():
            return JSONResponse({"error": "Invalid report length."}, status_code=400)
        if int(declared) > MAX_BODY_BYTES:
            return JSONResponse({"error": "Report is too large."}, status_code=413)

    received = bytearray()
    try:
        async with asyncio.timeout(3):
            async for chunk in request.stream():
                if len(received) + len(chunk) > MAX_BODY_BYTES:
                    return JSONResponse({"error": "Report is too large."}, status_code=413)
                received.extend(chunk)
    except TimeoutError:
        return JSONResponse({"error": "Report timed out."}, status_code=408)

    try:
        payload = json.loads(received)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError):
        return JSONResponse({"error": "Invalid report."}, status_code=400)
    directives = _directives(payload, media_type)
    if directives is None:
        return JSONResponse({"error": "Invalid report."}, status_code=400)
    if not _admit_count(len(directives)):
        return JSONResponse({"error": "Report receiver is busy."}, status_code=429,
                            headers={"Retry-After": "60"})

    for directive in directives:
        CSP_REPORTS.labels(directive=directive if directive in DIRECTIVE_BUCKETS else "other").inc()
    return Response(status_code=204, headers={"Cache-Control": "no-store"})
