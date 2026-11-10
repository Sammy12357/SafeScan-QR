"""Bound scan-upload request bodies before multipart parsing can spool them."""

from starlette.responses import HTMLResponse, JSONResponse

from .config import MAX_QR_UPLOAD_BYTES


MULTIPART_OVERHEAD_BYTES = 64 * 1024
UPLOAD_PATHS = {"/search_qr_api", "/api/scan/file"}


class _UploadBodyLimitExceeded(Exception):
    pass


class QRUploadBodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in UPLOAD_PATHS:
            return await self.app(scope, receive, send)

        limit = MAX_QR_UPLOAD_BYTES + MULTIPART_OVERHEAD_BYTES

        async def reject():
            headers = {
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            }
            if scope["path"] == "/search_qr_api":
                response = HTMLResponse(
                    "<!doctype html><html lang='en'><meta charset='utf-8'>"
                    "<title>QR upload too large</title><main><h1>QR upload too large</h1>"
                    "<p>Choose a smaller QR image or PDF and try again.</p>"
                    "<p><a href='/'>Back to SafeScan</a></p></main></html>",
                    status_code=413,
                    headers=headers,
                )
            else:
                response = JSONResponse({"error": "QR upload request is too large."}, status_code=413, headers=headers)
            await response(scope, receive, send)

        for name, value in scope.get("headers", []):
            if name.lower() == b"content-length":
                try:
                    declared_size = int(value)
                except ValueError:
                    break
                if declared_size > limit:
                    return await reject()
                break

        received = 0
        overflowed = False

        async def bounded_receive():
            nonlocal received, overflowed
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    overflowed = True
                    raise _UploadBodyLimitExceeded()
            return message

        async def guarded_send(message):
            # Starlette may turn a receive error into a 400 while parsing the
            # multipart form. Suppress that response and return the real 413.
            if not overflowed:
                await send(message)

        try:
            await self.app(scope, bounded_receive, guarded_send)
        except Exception:
            if not overflowed:
                raise
        if overflowed:
            await reject()
