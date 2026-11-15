# SafeScan legal and privacy control inventory

This is an engineering inventory, **not a statement of legal compliance or approved legal advice**. The public Terms, Privacy Policy, Cookie Policy, subscription terms, and international-user position need qualified attorney review. The evidence and unresolved questions are in `docs/legal/attorney-packet.md` and `docs/legal/research-log.md`.

## Controls implemented in code

- Google and Auth0 sign-in now hold a verified identity in a short-lived pending state until the account age check completes. The server sets the account minimum age to 16; birth year and birthday answer are not retained. A separate adult attestation gates new payments, wallet, airdrop, token, and Go Ghost features. Existing billing management remains accessible so cancellation is not blocked. See `hackabull/age_gate.py` and `docs/legal/age-gate.md`.
- Orbitron is hosted at SafeScan's own origin. The Google sign-in script loads on the login page, not the homepage. The profile picture may still be requested from a Google image host for a signed-in user. See `docs/legal/vendor-register.md`.
- Optional first-party scanner performance counts require consent; no session recorder or advertising pixel was found in the Phase 0 code audit. The cookie banner now describes those counts. Consent records include a timestamp, IP hash, locale and banner version.
- Waitlist addresses require an explicit opt-in and confirmation before marketing export. One-use signed unsubscribe links and a suppression list are implemented. Marketing email is disabled until SMTP, a stable signing secret, a verified legal sender name and a physical postal address are configured. See `docs/legal/email-operations.md`.
- Card Checkout requires displayed renewal terms, an unchecked consent box, an account-bound Stripe Checkout Session and a verified webhook event before access is granted. The success page alone does not grant access. A signed-in customer can reach the Stripe portal for cancellation. Card checkout remains closed until the owner verifies the Stripe and business settings in `docs/legal/phase-1-payment-release.md`.
- The site has privacy-request, opt-out, consent-log and incident-report routes. Their existence does not establish that every data source, vendor, backup and statutory deadline is covered.

## Open work and owner decisions

- **Attorney:** approve the real legal entity, contracting terms, refund exceptions, privacy and cookie disclosures, age thresholds, cross-border treatment, arbitration terms, and the proposed SQR/token position. Do not publish an invented company name or address.
- **Owner:** provide a real business name and postal address before enabling marketing email or card checkout; verify Stripe product, portal cancellation, receipts, webhooks, tax handling and the legacy Payment Link migration. The owner chose the proposed refund position: no refunds after a billing period starts, except where law requires otherwise.
- **Engineering:** complete the field-level data map, retention jobs, end-to-end data rights, third-party licence notices, listing dispute workflow, token off switch, accessibility review and regression gates in later legal phases. Confirm actual Render storage, logs, backups, vendor agreements and browser requests.
- **Release:** the backend age flow and mobile age client must be tested together before the backend change reaches production. Existing account identities with a mismatched provider subject require manual recovery; do not merge them by email alone.

This file tracks code state on the legal Phase 1 branch. Check the corresponding PR and live deployment before treating a control as available to customers.
