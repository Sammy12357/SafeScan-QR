---
name: go-ghost-recipe
description: Use when adding a Go Ghost broker, changing a broker recipe, or reviewing SafeScan broker removal and status behavior.
---

# Go Ghost broker workflow

Read `docs/security/go-ghost-browser-release-gate.md` and the current broker registry before making changes.

- Server-side browser automation remains disabled until the release gate is met. Keep profile details on the user's device; do not place them in URLs, logs, or SafeScan's database.
- Inspect the broker's current opt-out flow in a real browser before writing selectors. Stay within reviewed domains and stop on CAPTCHA or ambiguous selectors.
- Group sister sites only when they truly share an opt-out. Record the source and date of a verified flow.
- Use fictional personal data in fixtures. Cover layout changes, zero or multiple selector matches, and a manual fallback.
- Keep `not_found`, submitted, and confirmed removed states distinct. Mark removal confirmed only with evidence from a later check.
- Preserve the user's family-member attestation path when the flow applies to someone else.
