"""Small JSON-line request and operational events with an allowlisted schema.

Never pass URLs, IP addresses, tokens, exception messages, or arbitrary
metadata here. The helper accepts only bounded categories and counters.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from datetime import datetime, timezone

from starlette.requests import Request
from starlette.responses import JSONResponse


_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_EVENT = re.compile(r"[a-z][a-z0-9_.]{0,63}\Z")
_ROUTE = re.compile(r"/[A-Za-z0-9_./{}:-]{0,127}\Z")
_ERROR_TYPE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_LEVELS = {"info", "warning", "error"}


def request_id_from_scope(scope) -> str | None:
    state = scope.get("state")
    value = state.get("request_id") if isinstance(state, dict) else None
    return value if isinstance(value, str) and _REQUEST_ID.fullmatch(value) else None


def log_event(
    event: str,
    *,
    level: str = "info",
    request_id: str | None = None,
    method: str | None = None,
    route: str | None = None,
    status_code: int | None = None,
    duration_ms: int | None = None,
    error_type: str | None = None,
) -> None:
    """Write one bounded JSON line without accepting arbitrary log fields."""
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "level": level if isinstance(level, str) and level in _LEVELS else "warning",
        "event": event if isinstance(event, str) and _EVENT.fullmatch(event) else "invalid_event",
    }
    if isinstance(request_id, str) and _REQUEST_ID.fullmatch(request_id):
        payload["request_id"] = request_id
    if method is not None:
        payload["method"] = method if isinstance(method, str) and method in _METHODS else "OTHER"
    if route is not None:
        payload["route"] = route if isinstance(route, str) and _ROUTE.fullmatch(route) else "unmatched"
    if isinstance(status_code, int) and 100 <= status_code <= 599:
        payload["status"] = status_code
    if isinstance(duration_ms, int) and duration_ms >= 0:
        payload["duration_ms"] = min(duration_ms, 600_000)
    if error_type is not None:
        payload["error_type"] = (
            error_type if isinstance(error_type, str) and _ERROR_TYPE.fullmatch(error_type)
            else "Exception"
        )
    try:
        os.write(1, (json.dumps(payload, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii"))
    except OSError:
        # Logging must not turn a handled failure into another request failure.
        pass


class RequestIdLoggingMiddleware:
    """Add a server-generated ID and an outcome event to every HTTP response."""

    def __init__(self, app, decorate_error):
        self.app = app
        self.decorate_error = decorate_error

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        request_id = secrets.token_hex(16)
        scope.setdefault("state", {})["request_id"] = request_id
        started = time.monotonic()
        status_code = 500
        response_started = False
        response_complete = False

        async def send_with_request_id(message):
            nonlocal status_code, response_started, response_complete
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_started = True
                headers = [(key, value) for key, value in message.get("headers", ())
                           if key.lower() != b"x-request-id"]
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message = {**message, "headers": headers}
            elif message["type"] == "http.response.body" and not message.get("more_body", False):
                response_complete = True
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        except Exception as exc:
            log_event(
                "request.exception", level="error", request_id=request_id,
                method=scope.get("method"), route=getattr(scope.get("route"), "path", None),
                status_code=500, error_type=type(exc).__name__,
            )
            if not response_started:
                response = JSONResponse({"error": "Something went wrong on our end."}, status_code=500)
                self.decorate_error(Request(scope, receive=receive), response)
                await response(scope, receive, send_with_request_id)
            elif not response_complete:
                # Headers cannot be changed after streaming begins. Finish the
                # stream and record the failure without leaking its exception.
                await send({"type": "http.response.body", "body": b"", "more_body": False})
        finally:
            log_event(
                "request.completed", request_id=request_id, method=scope.get("method"),
                route=getattr(scope.get("route"), "path", None), status_code=status_code,
                duration_ms=max(0, round((time.monotonic() - started) * 1000)),
            )
