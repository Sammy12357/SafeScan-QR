# Phase 8 accessibility review

The before and after captures use the isolated mock server, synthetic accounts, reduced motion, and four views at 375, 768, and 1440 CSS pixels in dark and light themes. All 24 final pairs have the same image dimensions. The greatest mean absolute pixel difference is 0.160/255; the visible changes are color refinements and synthetic timestamps. The before branch is merged main `0169984`; the after branch contains Phase 8.

| Theme and width | Home | Admin users | Admin user detail | State gallery |
| --- | --- | --- | --- | --- |
| Dark 375 | [Before](screenshots/ui-phase-8/before/dark/375/home.jpg) / [After](screenshots/ui-phase-8/after/dark/375/home.jpg) | [Before](screenshots/ui-phase-8/before/dark/375/admin_users.jpg) / [After](screenshots/ui-phase-8/after/dark/375/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/dark/375/admin_user_drawer.jpg) / [After](screenshots/ui-phase-8/after/dark/375/admin_user_drawer.jpg) | [Before](screenshots/ui-phase-8/before/dark/375/states.jpg) / [After](screenshots/ui-phase-8/after/dark/375/states.jpg) |
| Dark 768 | [Before](screenshots/ui-phase-8/before/dark/768/home.jpg) / [After](screenshots/ui-phase-8/after/dark/768/home.jpg) | [Before](screenshots/ui-phase-8/before/dark/768/admin_users.jpg) / [After](screenshots/ui-phase-8/after/dark/768/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/dark/768/admin_user_drawer.jpg) / [After](screenshots/ui-phase-8/after/dark/768/admin_user_drawer.jpg) | [Before](screenshots/ui-phase-8/before/dark/768/states.jpg) / [After](screenshots/ui-phase-8/after/dark/768/states.jpg) |
| Dark 1440 | [Before](screenshots/ui-phase-8/before/dark/1440/home.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/home.jpg) | [Before](screenshots/ui-phase-8/before/dark/1440/admin_users.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/dark/1440/admin_user_drawer.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/admin_user_drawer.jpg) | [Before](screenshots/ui-phase-8/before/dark/1440/states.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/states.jpg) |
| Light 375 | [Before](screenshots/ui-phase-8/before/light/375/home.jpg) / [After](screenshots/ui-phase-8/after/light/375/home.jpg) | [Before](screenshots/ui-phase-8/before/light/375/admin_users.jpg) / [After](screenshots/ui-phase-8/after/light/375/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/light/375/admin_user_drawer.jpg) / [After](screenshots/ui-phase-8/after/light/375/admin_user_drawer.jpg) | [Before](screenshots/ui-phase-8/before/light/375/states.jpg) / [After](screenshots/ui-phase-8/after/light/375/states.jpg) |
| Light 768 | [Before](screenshots/ui-phase-8/before/light/768/home.jpg) / [After](screenshots/ui-phase-8/after/light/768/home.jpg) | [Before](screenshots/ui-phase-8/before/light/768/admin_users.jpg) / [After](screenshots/ui-phase-8/after/light/768/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/light/768/admin_user_drawer.jpg) / [After](screenshots/ui-phase-8/after/light/768/admin_user_drawer.jpg) | [Before](screenshots/ui-phase-8/before/light/768/states.jpg) / [After](screenshots/ui-phase-8/after/light/768/states.jpg) |
| Light 1440 | [Before](screenshots/ui-phase-8/before/light/1440/home.jpg) / [After](screenshots/ui-phase-8/after/light/1440/home.jpg) | [Before](screenshots/ui-phase-8/before/light/1440/admin_users.jpg) / [After](screenshots/ui-phase-8/after/light/1440/admin_users.jpg) | [Before](screenshots/ui-phase-8/before/light/1440/admin_user_drawer.jpg) / [After](screenshots/ui-phase-8/after/light/1440/admin_user_drawer.jpg) | [Before](screenshots/ui-phase-8/before/light/1440/states.jpg) / [After](screenshots/ui-phase-8/after/light/1440/states.jpg) |

## Error page comparisons

The 404 and 500 pages were rendered with a fixed synthetic request reference.
The paired captures use each branch's templates and CSS; they contain no
request details or personal data. Both pages kept identical dimensions before
and after the Phase 8 stylesheet cache update.

| Theme and width | 404 | 500 |
| --- | --- | --- |
| Dark 375 | [Before](screenshots/ui-phase-8/before/dark/375/error_404.jpg) / [After](screenshots/ui-phase-8/after/dark/375/error_404.jpg) | [Before](screenshots/ui-phase-8/before/dark/375/error_500.jpg) / [After](screenshots/ui-phase-8/after/dark/375/error_500.jpg) |
| Dark 768 | [Before](screenshots/ui-phase-8/before/dark/768/error_404.jpg) / [After](screenshots/ui-phase-8/after/dark/768/error_404.jpg) | [Before](screenshots/ui-phase-8/before/dark/768/error_500.jpg) / [After](screenshots/ui-phase-8/after/dark/768/error_500.jpg) |
| Dark 1440 | [Before](screenshots/ui-phase-8/before/dark/1440/error_404.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/error_404.jpg) | [Before](screenshots/ui-phase-8/before/dark/1440/error_500.jpg) / [After](screenshots/ui-phase-8/after/dark/1440/error_500.jpg) |
| Light 375 | [Before](screenshots/ui-phase-8/before/light/375/error_404.jpg) / [After](screenshots/ui-phase-8/after/light/375/error_404.jpg) | [Before](screenshots/ui-phase-8/before/light/375/error_500.jpg) / [After](screenshots/ui-phase-8/after/light/375/error_500.jpg) |
| Light 768 | [Before](screenshots/ui-phase-8/before/light/768/error_404.jpg) / [After](screenshots/ui-phase-8/after/light/768/error_404.jpg) | [Before](screenshots/ui-phase-8/before/light/768/error_500.jpg) / [After](screenshots/ui-phase-8/after/light/768/error_500.jpg) |
| Light 1440 | [Before](screenshots/ui-phase-8/before/light/1440/error_404.jpg) / [After](screenshots/ui-phase-8/after/light/1440/error_404.jpg) | [Before](screenshots/ui-phase-8/before/light/1440/error_500.jpg) / [After](screenshots/ui-phase-8/after/light/1440/error_500.jpg) |

## Browser checks

- Axe WCAG 2, 2.1, and 2.2 A/AA found zero violations in all 180 renders of the 30 Phase 7 synthetic route states at six width/theme combinations. The 404 and 500 pages passed all 12 combinations. Home, state gallery, admin users, and admin detail also passed their six combinations. Both camera implementations had no axe violations while the dialog was open.
- At 375 px, opening the drawer moved focus to its close button and removed `inert`; Escape closed it, restored `inert`, and returned focus to Menu. The drawer's Tab key stays inside while open.
- Keyboard activation of the hero Scan QR link and the drawer Scanner link moved focus to the scanner heading, including a direct `/#scanner` load. Closing the drawer explicitly returned focus to Menu; following its Scanner link did not. Chromium verified focus returning to Scan with camera after closing the camera dialog. The iPhone VoiceOver report that prompted this fix still needs a physical retest after deployment.
- Both camera variants focused Back on open, made background content inert, kept Tab inside the dialog, and returned focus to Scan with camera after Escape.
- Under `prefers-reduced-motion: reduce`, the scan-line animation computes to `0.001ms` and one iteration at every tested width and theme.
- Calculated contrast is 7.55:1 for dark footer labels, 5.15:1 for the dark focus ring against a panel, 6.32:1 for the light focus ring against white, and 5.60:1 for the light active admin badge.

These checks use headless Chromium and synthetic local data. The merged camera and navigation behavior should also be checked with VoiceOver in iPhone Safari before a release claim about screen-reader support.

## Slow network and offline check

An isolated Chromium session used 150 ms latency with 1.6 Mbps down and 750 kbps up, then held the threat-feed request. The loading state and `aria-busy` were visible. Dropping the connection mid-request produced a persistent offline error, a Try again button, and a cleared busy state. Reconnecting and activating Try again cleared the error. The [reproducible browser check](../../scripts/ui_phase8_network_qa.py) saved loading and error screenshots at all six width/theme combinations under [network captures](screenshots/ui-phase-8/network/dark/375/threat_feed_offline_error.jpg). This simulation covers the threat-feed path; it does not replace physical iPhone testing of camera/network behavior.

Four synthetic ambiguous-account admin states were captured before and after Phase 8 in both themes at 375, 768, and 1440 px: [users](screenshots/ui-phase-8/ambiguity/after/dark/375/admin_users_ambiguous.jpg), [user detail](screenshots/ui-phase-8/ambiguity/after/dark/375/admin_user_drawer_ambiguous.jpg), [airdrop](screenshots/ui-phase-8/ambiguity/after/dark/375/admin_airdrop_ambiguous.jpg), and [fraud](screenshots/ui-phase-8/ambiguity/after/dark/375/admin_fraud_unassigned.jpg). All 24 before/after pairs have matching dimensions; all 24 after renders are included in the 180-case axe run.

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
renders 30 synthetic, route-specific first-use, no-results, and no-access views
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
The threat-feed slow/offline path is covered by the browser check above, while
other request and timeout paths have focused tests. iPhone VoiceOver remains a
manual release check. The 404/500 and threat-feed error captures are included;
other route-specific error captures remain an open coverage gap.
