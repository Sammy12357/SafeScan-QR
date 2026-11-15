---
name: safescan-security-gate
description: Use when reviewing SafeScan security or changing authentication, accounts, roles, payments, uploads, admin access, user-owned data, or outbound URL fetching.
---

# SafeScan security review

Read the relevant code and tests before asserting that a control exists. Treat the rules below as target properties for new or changed flows; document legacy gaps and fix them in scoped work. Do not silently claim they are already enforced.

## Identity and authorization

- Validate token issuer, audience, expiry, signature, and verified email where the provider supplies it. Keep provider issuer and subject as the stable identity. Never merge a new provider identity into an account merely because email matches.
- Authorize before querying or changing privileged or user-owned records. Keep role changes in the authorized admin/bootstrap path.
- Check CSRF, rate limits, and trusted-proxy IP handling for state-changing routes.

## Data and requests

- Bound and validate untrusted input. Use parameterized SQL and escape user content in HTML and browser DOM updates.
- Keep secrets, tokens, private QR payloads, and Go Ghost profile details out of logs and URLs.
- Use the existing SSRF-safe fetch path for outbound URLs, including redirects.

## Payments

- Grant paid access only from a verified, replay-safe payment event. A success-page visit is not proof of payment.

## Known migration gaps

- `save_user_to_db` currently resolves accounts by email, and mobile Auth0 login strips provider prefixes from subjects. Review `hackabull/accounts.py` and `hackabull/routes_scan_auth.py` before adding connections.
- `/pay/alpha/success` currently writes an active subscription. Review `hackabull/routes_pages.py` and `hackabull/payments_stripe.py` before changing access or claiming webhook-only activation.

For a security fix, add a regression test that demonstrates the failure and its corrected behavior. See `docs/security/research-log.md` and the applicable release gates under `docs/security/`.
