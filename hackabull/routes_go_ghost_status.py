"""Reserved Go Ghost status endpoints; no status sync is publicly enabled."""

from __future__ import annotations

from fastapi.responses import JSONResponse

from .app_module import qr_app
from .go_ghost_status import GO_GHOST_STATUS_SYNC_AVAILABLE


# Changing the compile-time gate alone must not expose cookie-authenticated
# writes without session-bound CSRF, bounded rate limiting, canonical identity
# checks, and an extension authentication design.
if GO_GHOST_STATUS_SYNC_AVAILABLE:
    raise RuntimeError("Go Ghost status sync requires a security-reviewed route implementation")


def _unavailable() -> JSONResponse:
    return JSONResponse(
        {"error": "Go Ghost status sync is unavailable."},
        status_code=503,
        headers={"Cache-Control": "no-store"},
    )


@qr_app.get("/api/go-ghost/status", include_in_schema=False)
async def go_ghost_status_unavailable():
    return _unavailable()


@qr_app.put("/api/go-ghost/status/{broker_id}", include_in_schema=False)
async def go_ghost_status_write_unavailable(broker_id: str):
    return _unavailable()


@qr_app.post("/api/go-ghost/subjects", include_in_schema=False)
async def go_ghost_subject_create_unavailable():
    return _unavailable()


@qr_app.post("/api/go-ghost/subjects/{subject_id}/consent", include_in_schema=False)
async def go_ghost_consent_write_unavailable(subject_id: str):
    return _unavailable()
