"""Classify pre-interaction browser requests without retaining URL secrets."""

from __future__ import annotations

from urllib.parse import SplitResult, urlsplit


def _network_origin(url: str) -> tuple[str, str, int] | None:
    """Return an HTTP(S) or WS(S) origin without URL credentials or paths."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https", "ws", "wss"} or not parts.hostname:
            return None
        port = parts.port or (443 if parts.scheme in {"https", "wss"} else 80)
        return parts.scheme, parts.hostname.lower().rstrip("."), port
    except ValueError:
        return None


def _display_origin(origin: tuple[str, str, int]) -> str:
    scheme, host, port = origin
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if scheme in {"https", "wss"} else 80
    return f"{scheme}://{host}" + (f":{port}" if port != default_port else "")


def first_party_request(url: str, base_url: str) -> bool:
    """Match exact origins, mapping WS(S) to the matching HTTP(S) origin."""
    origin = _network_origin(url)
    if origin is None:
        return False
    scheme, host, port = origin
    scheme = {"ws": "http", "wss": "https"}.get(scheme, scheme)
    return (scheme, host, port) == _network_origin(base_url)


def unexpected_request(url: str, base_url: str, page_path: str, resource_type: str) -> str | None:
    """Return an unexpected destination origin, or None when no gate rule was broken.

    The audit blocks all outside requests, including the permitted login script.
    Only the existence of an attempted request matters here. The URL path,
    query and fragment are deliberately excluded from diagnostic output.
    """
    origin = _network_origin(url)
    if origin is None or first_party_request(url, base_url):
        return None
    parts: SplitResult = urlsplit(url)
    if (
        page_path == "/login"
        and resource_type == "script"
        and origin == ("https", "accounts.google.com", 443)
        and parts.path == "/gsi/client"
        and not parts.query
        and not parts.fragment
        and not parts.username
        and not parts.password
    ):
        return None
    return _display_origin(origin)


def record_attempt(url: str, resource_type: str, base_url: str, view: str,
                   page_path: str, theme: str, attempts: list[dict[str, str]]) -> None:
    """Record a safe diagnostic for an attempted third-party load."""
    origin = unexpected_request(url, base_url, page_path, resource_type)
    if origin is not None:
        attempts.append({"view": view, "path": page_path, "theme": theme,
                         "resource_type": resource_type, "destination": origin})
