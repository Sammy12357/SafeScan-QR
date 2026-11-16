"""Public search URLs and crawl policy for the Sqafe website.

Keep this list small: API, account, gated, and browser-only result pages are
not useful landing pages. Mobile clients still call the Render hostname.
"""

from __future__ import annotations

CANONICAL_ORIGIN = "https://sqafe.com"
RENDER_HOST = "safescan-qr.onrender.com"
OG_IMAGE_PATH = "/static/og-sqafe.png"

# This registry is the sole source for both the sitemap and indexable page
# metadata. Add a page only after its visible content and public claims have
# been reviewed. Generator and pricing await working production checks and
# checkout; the threat list and risk-engine page require separate claim review.
SEO_PAGE_COPY = {
    "/": {
        "title": "Check a QR Code Before Opening It | Sqafe",
        "description": (
            "Scan a QR code or paste its contents to review the destination and "
            "available risk signals before deciding whether to open it."
        ),
    },
    "/learn": {
        "title": "QR Code Safety and Quishing Guide | Sqafe",
        "description": (
            "Learn how QR phishing works, what a QR code can contain, and how to "
            "inspect links, payment requests, and wallet prompts before opening them."
        ),
    },
    "/contact": {
        "title": "Contact Sqafe | Support and Security Reports",
        "description": (
            "Find Sqafe contact options for account help, privacy questions, "
            "partnerships, and reporting a security concern."
        ),
    },
}
SITEMAP_PATHS = tuple(SEO_PAGE_COPY)

# Public HTML routes may move to the canonical host. Keep auth, account,
# checkout, and API routes on their requested host so existing sessions and
# mobile clients are not redirected across cookie origins.
PUBLIC_CANONICAL_PATHS = frozenset(SITEMAP_PATHS) | {
    "/accessibility",
    "/changelog",
    "/generate-qr",
    "/legal/cookie-policy",
    "/legal/license",
    "/legal/privacy-policy",
    "/legal/security",
    "/legal/terms-history",
    "/legal/terms-of-use",
    "/malicious-database",
    "/plans",
    "/product/getting-started",
    "/product/install",
    "/product/pricing",
    "/product/wedges",
    "/resources/architecture",
    "/resources/docs",
    "/resources/roadmap",
    "/risk-engine",
}

def public_canonical_path(path: str) -> str | None:
    """Normalize only known public page aliases, never arbitrary/API paths."""
    candidate = (path.rstrip("/") or "/").lower()
    return candidate if candidate in PUBLIC_CANONICAL_PATHS else None


def canonical_url(path: str) -> str:
    return CANONICAL_ORIGIN + path


def metadata_for_request(request) -> dict[str, str] | None:
    """Return reviewed metadata only for a canonical, public GET document.

    Scan POST results, duplicate home routes, noncanonical hosts, and all
    other HTML get the noindex fallback in the shared template partial.
    """
    path = request.url.path
    host = request.url.hostname or ""
    if request.method != "GET" or should_noindex_html(host, path, 200):
        return None
    copy = SEO_PAGE_COPY[path]
    return {
        **copy,
        "url": canonical_url(path),
        "image_url": canonical_url(OG_IMAGE_PATH),
    }


def canonical_redirect_url(host: str, path: str, query: str) -> str | None:
    canonical_path = public_canonical_path(path)
    if canonical_path is None:
        return None
    if host not in (RENDER_HOST, "www.sqafe.com", "sqafe.com"):
        return None
    if host == "sqafe.com" and path == canonical_path:
        return None
    destination = canonical_url(canonical_path)
    if query:
        # Preserve valid query bytes, including referral parameters; never
        # re-interpret them as part of the path or destination host.
        destination += "?" + query
    return destination


def should_noindex_html(host: str, path: str, status_code: int) -> bool:
    # Default closed for app, account, gated, duplicate, staging, and future
    # routes. A new page is indexed only after it is reviewed and added above.
    return status_code != 200 or host != "sqafe.com" or path not in SITEMAP_PATHS
