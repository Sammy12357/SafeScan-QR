"""Public error responses shared by page routes and JSON clients.

The catalogue contains text safe to show when the underlying exception may
carry configuration, provider, or database details. Route-specific validation
copy can be migrated to these codes without changing the API's `error` string.
"""

from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from typing import Mapping

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse

from .config import templates


@dataclass(frozen=True)
class Message:
    message: str
    hint: str
    status_code: int


ERRORS: dict[str, Message] = {
    "invalid_request": Message("We couldn't process that request.", "Refresh the page and try again.", 400),
    "authentication_required": Message("Sign in to continue.", "Open the sign-in page and try again.", 401),
    "access_denied": Message("You don't have access to this page.", "Return home or sign in with an account that has access.", 403),
    "not_found": Message("We can't find that page.", "Check the link or return home.", 404),
    "request_timeout": Message("That request took too long.", "Check your connection and try again.", 408),
    "conflict": Message("That change couldn't be completed.", "Refresh the page and try again.", 409),
    "gone": Message("This resource is no longer available.", "Return home to continue.", 410),
    "upload_too_large": Message("That file is too large.", "Choose a smaller image and try again.", 413),
    "unsupported_media": Message("We couldn't read that file type.", "Choose an image, SVG, or PDF and try again.", 415),
    "invalid_fields": Message("Some information is missing or invalid.", "Review the form and try again.", 422),
    "rate_limited": Message("You're going a bit fast.", "Wait a moment, then try again.", 429),
    "internal_error": Message("Something broke on our side.", "Try again in a minute.", 500),
    "upstream_unavailable": Message("A service SafeScan needs is unavailable.", "Try again in a moment.", 502),
    "service_unavailable": Message("SafeScan is briefly unavailable.", "Try again in a moment.", 503),
    "scanner_busy": Message("The scanner is busy.", "Wait a moment, then try again.", 503),
    "status_sync_unavailable": Message("Go Ghost status sync is unavailable.", "Use the manual steps for now.", 503),
    "go_ghost_identity_unavailable": Message("Go Ghost account identity is unavailable.", "Sign in again and try opening Go Ghost.", 503),
    "assisted_brokers_unavailable": Message("Assisted broker submissions are unavailable. Use Search, Opt out, and Copy details to complete the request in your browser.", "Use the manual steps for now.", 503),
    "upload_timed_out": Message("The upload took too long.", "Check your connection and try again.", 408),
    "origin_not_allowed": Message("This request could not be accepted.", "Open SafeScan directly and try again.", 403),
    "qr_payload_missing": Message("Add a QR code or paste its contents.", "Choose an image or paste decoded content, then scan again.", 400),
    "qr_payload_too_large": Message("That QR content is too large to check.", "Use a QR code with less content.", 400),
    "qr_not_found": Message("We couldn't find a QR code in that image.", "Try a sharper, closer photo with the whole code in frame.", 400),
    "qr_ambiguous": Message("We found more than one QR code.", "Aim at one code and scan again.", 400),
    "qr_unreadable": Message("We couldn't read that QR code.", "Try a sharper photo with the whole code in frame.", 400),
    "scan_incomplete": Message("We couldn't finish checking this link.", "Try again in a moment. Do not open the link until the checks finish.", 503),
    "qr_generation_blocked": Message("We can't make a branded QR code for this link.", "Review the scan result and use a destination that SafeScan can verify.", 400),
    "report_reason_invalid": Message("Choose a reason for the report.", "Select one of the available reasons and submit again.", 400),
    "url_required": Message("Add a web address to check.", "Paste a link beginning with http or https.", 400),
    "url_invalid": Message("That link isn't a web address we can check.", "Use a full link beginning with http or https.", 400),
    "url_private": Message("That link points to a private or local address.", "Use a public web address instead.", 400),
    "url_too_long": Message("That link is too long to check.", "Use a web address with 2,048 characters or fewer.", 400),
    "url_credentials": Message("We can't check a link with a username or password in it.", "Use a public web address without sign-in details.", 400),
    "wallet_address_invalid": Message("That wallet address isn't valid.", "Check the Solana address and try again.", 400),
    "wallet_challenge_missing": Message("We couldn't find a wallet verification to finish.", "Request a new verification challenge.", 400),
    "wallet_challenge_expired": Message("Your wallet verification expired.", "Request a new challenge and try again.", 400),
    "wallet_signature_invalid": Message("Signature verification failed.", "Request a new challenge and approve it in your wallet.", 400),
    "wallet_already_linked": Message("This wallet is already linked to another account.", "Use a different wallet or contact support.", 409),
    "wallet_not_found": Message("We couldn't find a connected wallet.", "Connect a wallet before trying to remove it.", 404),
    "wallet_connection_blocked": Message("Wallet connection could not be completed.", "Contact support for help.", 403),
    "username_invalid": Message("That username isn't available.", "Use 3 to 24 letters, numbers, or underscores.", 400),
    "username_taken": Message("That username is already taken.", "Choose a different username.", 400),
    "username_already_set": Message("Your username is already set.", "Your public name cannot be changed here.", 400),
    "email_invalid": Message("Enter a valid email address.", "Check the address and try again.", 400),
    "password_too_short": Message("Use a longer password.", "Enter at least 8 characters.", 400),
    "credentials_invalid": Message("Email or password is incorrect.", "Check both and try again.", 401),
    "account_exists": Message("This email is already linked to an account.", "Sign in instead.", 409),
    "already_signed_in": Message("You are already signed in.", "Sign out before creating another account.", 409),
    "payment_unavailable": Message("Solana payments aren't available right now.", "Use card checkout or try again later.", 503),
    "payment_network_unavailable": Message("We couldn't reach the Solana network.", "Try verifying your payment again in a moment.", 502),
    "payment_quote_missing": Message("We couldn't find a payment to verify.", "Open the payment page to start a new payment.", 400),
    "payment_quote_expired": Message("This payment quote expired.", "Open the payment page to generate a fresh quote.", 400),
    "discord_unavailable": Message("Discord linking isn't available right now.", "Try linking your account later.", 503),
    "broker_unsupported": Message("Assisted submission isn't available for this site.", "Use the manual opt-out steps instead.", 400),
    "profile_name_required": Message("Add a full name before submitting.", "Enter the name shown on the listing.", 400),
    "profile_email_required": Message("Add an email address before submitting.", "Enter an address where the broker can contact you.", 400),
}

_STATUS_CODES = {
    400: "invalid_request",
    401: "authentication_required",
    403: "access_denied",
    404: "not_found",
    408: "request_timeout",
    409: "conflict",
    410: "gone",
    413: "upload_too_large",
    415: "unsupported_media",
    422: "invalid_fields",
    429: "rate_limited",
    500: "internal_error",
    502: "upstream_unavailable",
    503: "service_unavailable",
}


def new_request_id() -> str:
    """An unguessable, log-friendly ID; never accept a caller-supplied value."""
    value = base64.b32encode(secrets.token_bytes(8)).decode("ascii").rstrip("=")
    return f"{value[:6]}-{value[6:]}"


def request_id_for(request: Request) -> str:
    request_id = getattr(request.state, "request_id", None)
    if not request_id:
        request_id = new_request_id()
        request.state.request_id = request_id
    return request_id


def _accept_preference(header: str, media_type: str) -> tuple[float, int]:
    """Return the quality and specificity of the best matching media range."""
    best = (0.0, -1)
    for part in header.split(","):
        segments = [segment.strip() for segment in part.split(";")]
        name = segments[0].lower()
        if name == media_type:
            specificity = 2
        elif name == media_type.split("/", 1)[0] + "/*":
            specificity = 1
        elif name == "*/*":
            specificity = 0
        else:
            continue
        quality = 1.0
        for parameter in segments[1:]:
            if parameter.lower().startswith("q="):
                try:
                    quality = float(parameter[2:])
                except ValueError:
                    quality = 0.0
                break
        if not 0 <= quality <= 1:
            quality = 0.0
        if specificity > best[1] or (specificity == best[1] and quality > best[0]):
            best = (quality, specificity)
    return best


def wants_json_error(request: Request) -> bool:
    path = request.url.path
    if (
        path.startswith(("/api/", "/webhooks/"))
        or path == "/metrics" or path.startswith("/metrics/")
        or path == "/health" or path.startswith("/health/")
    ):
        return True
    if request.headers.get("x-requested-with", "").lower() == "fetch":
        return True
    accept = request.headers.get("accept", "")
    json_quality, json_specificity = _accept_preference(accept, "application/json")
    html_quality, html_specificity = _accept_preference(accept, "text/html")
    # Native fetch() sends */* while a browser form navigation explicitly
    # prefers text/html. The mobile app uses this HTML route as a scan fallback:
    # keep its successful HTML result, but make failures machine-readable.
    if path == "/search_qr_api" and html_specificity < 1:
        return True
    return json_quality > 0 and (json_quality > html_quality or (json_quality == html_quality and json_specificity > html_specificity))


def _retry_seconds(headers: Mapping[str, str]) -> int | None:
    raw = next((value for key, value in headers.items() if key.lower() == "retry-after"), None)
    if raw is None:
        return None
    try:
        seconds = int(raw)
    except ValueError:
        return None
    return min(max(seconds, 1), 86400)


def error_response(
    request: Request,
    status_code: int,
    *,
    code: str | None = None,
    message: str | None = None,
    hint: str | None = None,
    field: str | None = None,
    headers: Mapping[str, str] | None = None,
    extra: Mapping[str, object] | None = None,
):
    """Render an error with the same status and request ID in either format."""
    resolved_code = code if code in ERRORS else _STATUS_CODES.get(status_code, "invalid_request")
    entry = ERRORS[resolved_code]
    # Exception text from a server-side failure can reveal credentials or
    # upstream responses. Only catalogue copy reaches the visitor for 5xx.
    public_message = entry.message if status_code >= 500 else (message or entry.message)
    public_hint = entry.hint if status_code >= 500 else (hint or entry.hint)
    response_headers = dict(headers or {})
    response_headers["Cache-Control"] = "no-store"
    response_headers["X-Request-ID"] = request_id_for(request)
    retry_after = _retry_seconds(response_headers) if status_code == 429 else None
    if status_code == 429 and retry_after is None:
        retry_after = 60
        response_headers["Retry-After"] = str(retry_after)

    if wants_json_error(request):
        body: dict[str, object] = dict(extra or {})
        body.update({"error": public_message, "code": resolved_code, "request_id": response_headers["X-Request-ID"]})
        if public_hint:
            body["hint"] = public_hint
        if field:
            body["field"] = field
        if retry_after is not None:
            body["retryAfter"] = retry_after
        return JSONResponse(body, status_code=status_code, headers=response_headers)

    page = {401: "403", 403: "403", 404: "404", 429: "429", 500: "500", 502: "503", 503: "503"}.get(status_code, "400")
    cached_user = getattr(request.state, "session_user", None)
    context = {
        "request": request,
        "status_code": status_code,
        "error_message": public_message,
        "hint": public_hint,
        "request_id": response_headers["X-Request-ID"],
        "retry_after": retry_after,
        "request_method": request.method,
        "logged_in": bool(cached_user),
        "active_nav": "",
        "profile_display_name": (cached_user or {}).get("display_name") or "Safe Scanner",
        "profile_subtitle": (cached_user or {}).get("email") or "",
        "profile_picture": (cached_user or {}).get("picture") or "",
        "is_admin": (cached_user or {}).get("role") in ("admin", "owner"),
    }
    try:
        return templates.TemplateResponse(f"errors/{page}.html", context, status_code=status_code, headers=response_headers)
    except Exception:
        # The final error response must still work if the template loader fails.
        fallback = "<!doctype html><html lang='en'><head><meta name='robots' content='noindex'><title>SafeScan</title></head><body><h1>SafeScan couldn't show this page</h1><p>Try again in a moment.</p><p>Reference: " + response_headers["X-Request-ID"] + "</p><a href='/'>Home</a></body></html>"
        return HTMLResponse(fallback, status_code=status_code, headers=response_headers)
