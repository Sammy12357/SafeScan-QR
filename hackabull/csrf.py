"""Narrow browser-origin guard for high-impact admin actions."""

from fastapi import HTTPException, Request

from .config import ALLOWED_ORIGINS


def require_same_origin_action(request: Request) -> None:
    """Require an allowed browser Origin or explicit same-origin fetch metadata.

    A missing Origin by itself is not evidence of a same-origin request. This
    guard is intentionally limited to sensitive actions until Phase 4 adds
    synchronizer tokens for all cookie-authenticated mutations.
    """
    origin = request.headers.get("origin")
    fetch_site = request.headers.get("sec-fetch-site")
    if (
        (fetch_site and fetch_site != "same-origin")
        or (origin and origin not in ALLOWED_ORIGINS)
        or (not origin and fetch_site != "same-origin")
    ):
        raise HTTPException(status_code=403, detail="You do not have permission to do this.")
