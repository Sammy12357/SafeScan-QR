# Phase 7 waitlist confirmation

`POST /waitlist` sends a 30-minute confirmation link when SMTP is configured.
It stores only a SHA-256 token hash and does not add the address to the
deliverable waitlist. The email link opens a confirmation page; only a CSRF
protected `POST /waitlist/confirm` marks the address confirmed. The token is
consumed once under a SQLite write lock. Invalid, expired, or replayed tokens
do not add a signup. A failed or unavailable SMTP send leaves no pending
address and returns an unavailable page.

The schema adds `waitlist_signups.confirmed_at`. Existing rows receive `NULL`:
they were collected without mailbox proof and are excluded from the admin
waitlist and CSV export until the address holder confirms. They are preserved
for owner review; no old address is silently treated as verified.

Before release:

1. Configure and test SMTP and `APP_URL` on the intended public domain. Check
   the whole email link and confirmation on a real mailbox. If SMTP is absent,
   the form visibly returns 503 and creates no signup.
2. Configure Cloudflare Turnstile for the `waitlist` action and verify its
   site and secret keys, CSP, and widget on the public pages. Never accept a
   missing or failed challenge in production.
3. Review legacy waitlist rows and any newsletter export/send process. Use
   only rows with `confirmed_at IS NOT NULL` for future mail. Do not backfill
   confirmations from the existence of an old row.
4. Keep one Render worker/instance until shared rate limiting and job state
   are available. Confirm the daily per-address and hourly IP budgets on the
   deployed ingress.
