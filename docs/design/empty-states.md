# Phase 7 empty states

Empty views use the shared `empty_state` Jinja macro from Phase 3. Each state has a heading, one short explanation, and a link to a useful next step. The macro supplies `role="status"` and a nonverbal icon. Filtered results explain that the filter returned no matches and link to the unfiltered view.

The macro accepts a heading level so states inside an existing section heading use `h3`; standalone states use `h2` after the page heading.

This follows the [Carbon empty-state pattern](https://www.carbondesignsystem.com/building-blocks/core/patterns/empty-states), which recommends concise context and one primary next step, with distinct copy for first use and no search results. [Atlassian's empty-state guidance](https://atlassian.design/components/empty-state) also calls for an accessible heading and a primary action that recommends the best next step.

| View | Empty condition | Action |
|---|---|---|
| History | Signed out; no saved scans | Sign in; scan a QR |
| Leaderboard | No rankings, including after live refresh | Scan a QR |
| Profile | No public username; Discord unlinked | Choose a username; link Discord |
| Scan result | No visible risk-reason rows | Scan another QR |
| Go Ghost | No reviewed details; empty broker registry | Add details; use search cleanup links |
| Dashboard | No scan chart, verdicts, signups, reports, or activity | Open the corresponding admin view |
| Admin user detail | No verified wallet, fraud flags, scans, or activity for an existing account | Open the related admin view |
| Admin tables | Users, scans, waitlist, reports, blocklist, wallets, fraud flags, audit logs, API keys, consent log | Open a relevant view or create an API key |
| Admin filtered tables | Users, scans, waitlist, audit logs | Clear filters |

The Go Ghost broker search is manual and happens on external sites. SafeScan cannot infer that a person has no matching listing, so the page does not claim “nothing found” from an empty local table. The fallback appears only if the local broker registry is empty.

The token page already presents wallet connection with its own button, and the plans page is static content. The malicious-domain database has separate no-data and no-match cases rendered by its client script; the Phase 6 work updates those through `UIStates`.

## Visual review

The [comparison matrix](screenshots/ui-phase-7/README.md) covers 26 before and after views at 375, 768, and 1440 pixels in both themes, using synthetic data and no application server. The [capture script](../../scripts/ui_phase7_screenshots.py) reproduces the set with each version's own static assets. Representative pairs:

- [History before](screenshots/ui-phase-7/before/dark/375/history.jpg) · [after](screenshots/ui-phase-7/after/dark/375/history.jpg)
- [Leaderboard before](screenshots/ui-phase-7/before/dark/768/leaderboard.jpg) · [after](screenshots/ui-phase-7/after/dark/768/leaderboard.jpg)
- [Profile before](screenshots/ui-phase-7/before/light/1440/profile.jpg) · [after](screenshots/ui-phase-7/after/light/1440/profile.jpg)
- [Go Ghost before](screenshots/ui-phase-7/before/light/1440/go_ghost.jpg) · [after](screenshots/ui-phase-7/after/light/1440/go_ghost.jpg)
- [Admin users before](screenshots/ui-phase-7/before/dark/375/admin_users.jpg) · [after](screenshots/ui-phase-7/after/dark/375/admin_users.jpg)
- [Admin user detail before](screenshots/ui-phase-7/before/dark/1440/admin_user_drawer.jpg) · [after](screenshots/ui-phase-7/after/dark/1440/admin_user_drawer.jpg)
- [Consent log before](screenshots/ui-phase-7/before/light/768/consent_log.jpg) · [after](screenshots/ui-phase-7/after/light/768/consent_log.jpg)

The capture script blocks application JavaScript and hides consent overlays to isolate the empty-state layout. Runtime toggling is checked by the existing Go Ghost and leaderboard tests.
