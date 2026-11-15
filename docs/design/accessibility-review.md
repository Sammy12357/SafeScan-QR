# Phase 8 accessibility review

The before and after captures use the isolated mock server, synthetic accounts, reduced motion, and the same three views at 375, 768, and 1440 CSS pixels in dark and light themes. All 18 pairs have the same image dimensions. The greatest mean absolute pixel difference is 0.345/255; the visible changes are color refinements and synthetic timestamps.

| Theme and width | Home | Admin users | State gallery |
| --- | --- | --- | --- |
| Dark 375 | [Before](screenshots/ui-phase-8/before/dark/375/home.jpg) / [After](screenshots/ui-phase-8/after/dark/375/home.jpg) | [Before](screenshots/ui-phase-8/before/dark/375/admin_users.jpg) / [After](screenshots/ui-phase-8/after/dark/375/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/dark/375/states.jpg) / [After](screenshots/ui-phase-8/after/dark/375/states.jpg) |
| Dark 768 | [Before](screenshots/ui-phase-8/before/dark/768/home.jpg) / [After](screenshots/ui-phase-8/after/dark/768/home.jpg) | [Before](screenshots/ui-phase-8/before/dark/768/admin_users.jpg) / [After](screenshots/ui-phase-8/after/dark/768/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/dark/768/states.jpg) / [After](screenshots/ui-phase-8/after/dark/768/states.jpg) |
| Dark 1440 | [Before](screenshots/ui-phase-8/before/dark/1440/home.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/home.jpg) | [Before](screenshots/ui-phase-8/before/dark/1440/admin_users.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/dark/1440/states.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/states.jpg) |
| Light 375 | [Before](screenshots/ui-phase-8/before/light/375/home.jpg) / [After](screenshots/ui-phase-8/after/light/375/home.jpg) | [Before](screenshots/ui-phase-8/before/light/375/admin_users.jpg) / [After](screenshots/ui-phase-8/after/light/375/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/light/375/states.jpg) / [After](screenshots/ui-phase-8/after/light/375/states.jpg) |
| Light 768 | [Before](screenshots/ui-phase-8/before/light/768/home.jpg) / [After](screenshots/ui-phase-8/after/light/768/home.jpg) | [Before](screenshots/ui-phase-8/before/light/768/admin_users.jpg) / [After](screenshots/ui-phase-8/after/light/768/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/light/768/states.jpg) / [After](screenshots/ui-phase-8/after/light/768/states.jpg) |
| Light 1440 | [Before](screenshots/ui-phase-8/before/light/1440/home.jpg) / [After](screenshots/ui-phase-8/after/light/1440/home.jpg) | [Before](screenshots/ui-phase-8/before/light/1440/admin_users.jpg) / [After](screenshots/ui-phase-8/after/light/1440/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/light/1440/states.jpg) / [After](screenshots/ui-phase-8/after/light/1440/states.jpg) |

## Browser checks

- Axe WCAG 2, 2.1, and 2.2 A/AA found no violations on home, state gallery, or admin users across all six width/theme combinations. Both camera implementations also had no axe violations while the dialog was open.
- At 375 px, opening the drawer moved focus to its close button and removed `inert`; Escape closed it, restored `inert`, and returned focus to Menu. The drawer's Tab key stays inside while open.
- Both camera variants focused Back on open, made background content inert, kept Tab inside the dialog, and returned focus to Scan with camera after Escape.
- Under `prefers-reduced-motion: reduce`, the scan-line animation computes to `0.001ms` and one iteration at every tested width and theme.
- Calculated contrast is 7.55:1 for dark footer labels, 5.15:1 for the dark focus ring against a panel, 6.32:1 for the light focus ring against white, and 5.60:1 for the light active admin badge.

These checks use headless Chromium and synthetic local data. The merged camera and navigation behavior should also be checked with VoiceOver in iPhone Safari before a release claim about screen-reader support.

## Mock state fixtures

The mock-only `/__states?__state=` switch renders allowlisted synthetic empty, loading, error, notice, and content samples without using request text in the page. The screenshot harness captured all five groups at each width and theme below. The route is 404 outside `MOCK_MODE`; the production home page ignores the query parameter.

Headless Chromium returned HTTP 200 for all 30 fixture views, and axe found zero WCAG 2, 2.1, or 2.2 A/AA violations in those 30 renders.

| Theme and width | Empty | Loading | Error | Notice | Content |
| --- | --- | --- | --- | --- | --- |
| Dark 375 | [View](screenshots/ui-phase-8/fixtures/dark/375/states_empty.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/375/states_loading.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/375/states_error.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/375/states_notice.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/375/states_content.jpg) |
| Dark 768 | [View](screenshots/ui-phase-8/fixtures/dark/768/states_empty.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/768/states_loading.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/768/states_error.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/768/states_notice.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/768/states_content.jpg) |
| Dark 1440 | [View](screenshots/ui-phase-8/fixtures/dark/1440/states_empty.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/1440/states_loading.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/1440/states_error.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/1440/states_notice.jpg) | [View](screenshots/ui-phase-8/fixtures/dark/1440/states_content.jpg) |
| Light 375 | [View](screenshots/ui-phase-8/fixtures/light/375/states_empty.jpg) | [View](screenshots/ui-phase-8/fixtures/light/375/states_loading.jpg) | [View](screenshots/ui-phase-8/fixtures/light/375/states_error.jpg) | [View](screenshots/ui-phase-8/fixtures/light/375/states_notice.jpg) | [View](screenshots/ui-phase-8/fixtures/light/375/states_content.jpg) |
| Light 768 | [View](screenshots/ui-phase-8/fixtures/light/768/states_empty.jpg) | [View](screenshots/ui-phase-8/fixtures/light/768/states_loading.jpg) | [View](screenshots/ui-phase-8/fixtures/light/768/states_error.jpg) | [View](screenshots/ui-phase-8/fixtures/light/768/states_notice.jpg) | [View](screenshots/ui-phase-8/fixtures/light/768/states_content.jpg) |
| Light 1440 | [View](screenshots/ui-phase-8/fixtures/light/1440/states_empty.jpg) | [View](screenshots/ui-phase-8/fixtures/light/1440/states_loading.jpg) | [View](screenshots/ui-phase-8/fixtures/light/1440/states_error.jpg) | [View](screenshots/ui-phase-8/fixtures/light/1440/states_notice.jpg) | [View](screenshots/ui-phase-8/fixtures/light/1440/states_content.jpg) |

## Coverage and limits

The mock screenshot inventory names 55 browser route variants. Phase 7 also
renders 26 synthetic, route-specific first-use, no-results, and no-access views
from the real Jinja templates. Their paired captures are in the
[Phase 7 comparison matrix](screenshots/ui-phase-7/README.md). The five
`/__states?__state=` groups above cover the shared component variants in all
six width/theme combinations. The switch only affects this gallery and is
unavailable outside `MOCK_MODE`.

The gallery does not reproduce every route's loading, error, and content
transition in the [state inventory](state-inventory.md). Scanner progress,
history and leaderboard refreshes, wallet/provider waits, Go Ghost actions,
and admin mutations need controlled requests or provider behavior, which a
single page query parameter cannot safely model. Static documents have no
meaningful loading or empty panel, and the one-time API-key reveal is
intentionally excluded from automated captures because it contains a secret.
The relevant request and timeout paths are covered by focused tests; slow
network and offline behavior, plus iPhone VoiceOver, remain manual release
checks. Route-specific error captures remain an open coverage gap rather than
a demonstrated pass.
