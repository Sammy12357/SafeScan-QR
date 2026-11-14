"""Bound request bodies before FastAPI parses JSON or form fields."""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from starlette.requests import Request
from starlette.responses import JSONResponse


UPLOAD_BODY_LIMIT = 10 * 1024 * 1024
JSON_BODY_LIMIT = 64 * 1024
DEFAULT_BODY_LIMIT = 16 * 1024
BODY_READ_TIMEOUT_SECONDS = 15
UPLOAD_PATHS = frozenset({"/search_qr_api", "/api/scan/file"})


class BodySizeLimitMiddleware:
    """Pure ASGI guard for declared and streamed request body sizes.

    The scanner's existing upload middleware already counts each streamed
    chunk, applies a read deadline, and caps the body below 10 MB. Preserve
    that guard's per-client admission check before it reads upload bytes.
    Other routes are buffered only up to their much smaller limits, then
    replayed to FastAPI for normal parsing.
    """

    def __init__(self, app, decorate_error: Callable):
        self.app = app
        self.decorate_error = decorate_error

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        headers = scope.get("headers", ())
        upload = method == "POST" and path in UPLOAD_PATHS
        content_type = next(
            (value.decode("latin-1").split(";", 1)[0].strip().lower()
             for key, value in headers if key.lower() == b"content-type"),
            "",
        )
        if upload:
            limit = UPLOAD_BODY_LIMIT
        elif content_type == "application/json" or content_type.endswith("+json"):
            limit = JSON_BODY_LIMIT
        else:
            limit = DEFAULT_BODY_LIMIT

        declared = [value for key, value in headers if key.lower() == b"content-length"]
        if len(declared) > 1 or (declared and (len(declared[0]) > 20 or not declared[0].isdigit())):
            return await self._reject(scope, receive, send, 400, "Invalid Content-Length.")
        if declared and int(declared[0]) > limit:
            return await self._reject(scope, receive, send, 413, "Request body is too large.")

        if upload:
            # This middleware sits inside the existing QR upload admission
            # guard, which enforces a lower streamed-byte ceiling and timeout.
            return await self.app(scope, receive, send)

        # Streaming HTTP clients may omit Content-Length. Stop reading at the
        # first chunk that exceeds the selected route budget.
        body = bytearray()
        rejection = None
        try:
            async with asyncio.timeout(BODY_READ_TIMEOUT_SECONDS):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    if message["type"] != "http.request":
                        rejection = (400, "Invalid request body.")
                        break
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > limit:
                        rejection = (413, "Request body is too large.")
                        break
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await self._reject(scope, receive, send, 408, "Request body timed out.")
        if rejection is not None:
            return await self._reject(scope, receive, send, *rejection)

        first = True

        async def replay():
            nonlocal first
            if first:
                first = False
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)

    async def _reject(self, scope, receive, send, status_code, detail):
        response = JSONResponse({"error": detail}, status_code=status_code)
        self.decorate_error(Request(scope, receive=receive), response)
        await response(scope, receive, send)
