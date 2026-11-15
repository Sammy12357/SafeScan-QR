"""Reserved Go Ghost status endpoints; no status sync is publicly enabled."""

from __future__ import annotations

from fastapi import Request

from .app_module import qr_app
from .errors import error_response
from .go_ghost_status import GO_GHOST_STATUS_SYNC_AVAILABLE


# Changing the compile-time gate alone must not expose cookie-authenticated
# writes without session-bound CSRF, bounded rate limiting, canonical identity
# checks, and an extension authentication design.
if GO_GHOST_STATUS_SYNC_AVAILABLE:
    raise RuntimeError("Go Ghost status sync requires a security-reviewed route implementation")


def _unavailable(request: Request):
    return error_response(request, 503, code="status_sync_unavailable")


@qr_app.get("/api/go-ghost/status", include_in_schema=False)
async def go_ghost_status_unavailable(request: Request):
    return _unavailable(request)


@qr_app.put("/api/go-ghost/status/{broker_id}", include_in_schema=False)
async def go_ghost_status_write_unavailable(request: Request, broker_id: str):
    return _unavailable(request)


@qr_app.post("/api/go-ghost/subjects", include_in_schema=False)
async def go_ghost_subject_create_unavailable(request: Request):
    return _unavailable(request)


@qr_app.post("/api/go-ghost/subjects/{subject_id}/consent", include_in_schema=False)
async def go_ghost_consent_write_unavailable(request: Request, subject_id: str):
    return _unavailable(request)
