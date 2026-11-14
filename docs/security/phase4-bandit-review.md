# Phase 4 Bandit B704 review

Phase 4 uses `markupsafe.Markup` for 18 route responses that pass server-authored
HTML into the existing legal page shell. Bandit 1.9.4 reports each call as B704.
The exact line and surrounding-code digest for every call is in
`.github/security/bandit-baseline.json`; changing one requires a new review.

The `body` arguments at those call sites are literal strings assigned inside
the route. `TERMS_HTML` and `COOKIE_POLICY_HTML` are server-authored constants.
`PRIVACY_POLICY_HTML` includes the configured contact address, which is
HTML-escaped for both text and attribute contexts in `admin_data.py`. The
Phase 4 tests inject HTML into that setting and confirm it is escaped. Dynamic
account, payment, consent, and admin values use autoescaped Jinja partials.
The static test in `tests/test_output_encoding.py` rejects f-string HTML in
route modules and arbitrary template `|safe` filters.

This baseline records the current narrow exception; new dynamic HTML should
use Jinja templates, not `Markup`.

Phase 5 (2026-11-14): input validation edits moved these calls in
`routes_pages.py`. All 18 `Markup(...)` call lines were compared with the
previous Phase 5 commit and are identical. The exact baseline was refreshed
for their new line numbers and surrounding-code digests; the other eight
Bandit findings are unchanged.
