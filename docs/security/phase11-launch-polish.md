# Phase 11 launch polish and copy audit

## What changed

- Server-rendered pages share a single title, description, canonical URL, and favicon partial. Public pages also use Open Graph and Twitter metadata with a pink-and-black 1200 × 630 PNG social card. Account, admin, sign-in, consent-log, and error pages carry `noindex` and omit social-preview metadata.
- Browser navigation gets static 404 and 500 pages. API paths and JSON clients keep JSON errors. Internal exception text is not rendered or logged with user-supplied paths.
- `/robots.txt` points to `/sitemap.xml`; the sitemap lists only public routes. The legacy static Go Ghost page points crawlers to the current `/go-ghost` route and is `noindex`.
- Consent, privacy, and cookie wording now matches the current count-only scanner endpoint: the browser sends count-only events only after an opt-in stored in local storage; the server aggregates them and does not store individual scanner events. The consent choice itself is recorded separately. Operational request metrics and abuse controls run regardless of optional scanner analytics.

## Asset and release gates

1. Confirm the live public host before release. `PUBLIC_SITE_ORIGIN` defaults to `https://sqafe.com`; set it in Render if the canonical host differs. Check the custom-domain certificate and redirects, then fetch `/robots.txt`, `/sitemap.xml`, and one page's canonical/OG URL over HTTPS.
2. The pink `static/safescan-logo.svg` is the favicon. `static/safescan-social-card.png` is generated from its exact QR tile layout and current page colors by `python scripts/build_social_card.py` (Pillow required). Preview the PNG after any brand change. After deployment, fetch the absolute image URL and check its rendering in Discord and social link previews; platforms can cache old cards.
3. Check the public privacy and cookie pages with counsel before launch. This pass aligns analytics and storage descriptions with the implementation; it does not certify the policy's broader legal claims or retention operations.
4. Verify how the production edge handles any request/access logs and cookies. The application telemetry endpoint does not persist individual events, but host/platform logging may have a separate retention policy.

## Verification

`tests/test_launch_polish.py` covers browser/API error negotiation, secret-free 500 responses, rendered public and private heads, crawler endpoints and live sitemap paths, favicon and social card delivery and dimensions, image `alt` attributes, and consent text. `tests/test_scanner_telemetry.py` covers accepted count fields and rejection of QR text, photos, and identifiers.
