# Phase 11 launch polish and copy audit

## What changed

- Server-rendered pages share a single title, description, canonical URL, favicon, Open Graph text, and Twitter text partial. Account, admin, sign-in, consent-log, and error pages carry `noindex`.
- Browser navigation gets static 404 and 500 pages. API paths and JSON clients keep JSON errors. Internal exception text is not rendered or logged with user-supplied paths.
- `/robots.txt` points to `/sitemap.xml`; the sitemap lists only public routes. The legacy static Go Ghost page points crawlers to the current `/go-ghost` route and is `noindex`.
- Consent, privacy, and cookie wording now matches the current count-only scanner endpoint: the browser sends count-only events only after an opt-in stored in local storage; the server aggregates them and does not store individual scanner events. The consent choice itself is recorded separately. Operational request metrics and abuse controls run regardless of optional scanner analytics.

## Asset and release gates

1. Confirm the live public host before release. `PUBLIC_SITE_ORIGIN` defaults to `https://sqafe.com`; set it in Render if the canonical host differs. Check the custom-domain certificate and redirects, then fetch `/robots.txt`, `/sitemap.xml`, and one page's canonical/OG URL over HTTPS.
2. The pink `static/safescan-logo.svg` is suitable as the favicon. The available raster `static/safescan-profile-static.png` has the old green branding, so there is deliberately **no `og:image` or `twitter:image`**. Create and review a current-brand social card before adding those tags; some social platforms do not support SVG preview images.
3. Check the public privacy and cookie pages with counsel before launch. This pass aligns analytics and storage descriptions with the implementation; it does not certify the policy's broader legal claims or retention operations.
4. Verify how the production edge handles any request/access logs and cookies. The application telemetry endpoint does not persist individual events, but host/platform logging may have a separate retention policy.

## Verification

`tests/test_launch_polish.py` covers browser/API error negotiation, secret-free 500 responses, rendered public and private heads, crawler endpoints and live sitemap paths, favicon delivery, image `alt` attributes, and consent text. `tests/test_scanner_telemetry.py` covers accepted count fields and rejection of QR text, photos, and identifiers.
