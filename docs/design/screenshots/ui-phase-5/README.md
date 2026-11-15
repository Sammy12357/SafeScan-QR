# Phase 5 form and message review

The `normal/` folder contains login, profile, data request, Alpha payment, and waitlist pages at 375, 768, and 1440 CSS pixels in dark and light themes. They were refreshed after rebasing onto merged Phase 4, using the Phase 0 `scripts/ui_screenshots.py` harness with a throwaway database and local mock accounts.

The `error/` folder contains four server validation states at 375 and 1440 CSS pixels in both themes. The camera used synthetic values (`bad-email`, `person@example.test`, and `bad name`) and temporarily disabled browser-native form validation so the server-side response could be inspected. No real account or payment data appears in these files. The error screenshots were captured through the same isolated local server environment as the Phase 0 harness.

The `admin-error/` folder adds owner-only user deletion, API key expiry, and breach-report validation at 375 and 1440 CSS pixels in both themes. The mock owner account and all entered values are synthetic.

The screenshots verify visible alerts, retained non-secret input, and layout at the recorded widths. They do not replace a keyboard and VoiceOver pass on a physical device. In production, local email/password sign-in is disabled; the register screenshots use the mock-mode form to check its server validation path.
