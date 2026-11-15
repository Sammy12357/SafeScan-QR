# Waitlist email operations

This is an internal engineering runbook, not an approved marketing or privacy disclosure. Public policy wording still needs attorney review.

## Configuration before sending

1. Set `APP_URL` to the public HTTPS origin that serves the waitlist routes. If the Render subdomain is disabled, use the verified custom domain.
2. Set `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and a real `EMAIL_FROM` address. Set a stable random `EMAIL_TOKEN_SECRET` of at least 32 bytes. Without these, the waitlist form reports that email updates are unavailable and stores no new request.
3. Before **marketing** email is enabled, the business owner must supply and verify `COMPANY_LEGAL_NAME` and a physical `COMPANY_POSTAL_ADDRESS`. Both are intentionally blank in `.env.example`. The code rejects blank/common placeholder values but cannot verify that an entered entity or address is legally correct.
4. Confirm the SMTP provider accepts the sender domain and that `APP_URL` links work on the live site. Do not send product updates until the legal owner approves the message, recipient scope, and relevant policy text.

## Consent and delivery behavior

- The form requires an explicit checkbox. It records email, source, timestamp and consent version as **pending**, then sends only a confirmation message. Opening the link shows a form; the user must press **Confirm updates** to activate the subscription. Existing waitlist records have no confirmed consent after migration and are excluded from marketing exports.
- `waitlist_email_tokens` stores hashes, not bearer tokens. Confirmation links expire after 24 hours. A new request invalidates earlier unconsumed confirmation links. Confirmation and unsubscribe actions are single-use; repeated unsubscribe requests remain idempotently successful while suppression is active.
- `send_waitlist_update` is the only current product-update send path. It requires a confirmed address, checks suppression before and immediately before SMTP delivery, adds sender/address/unsubscribe text, and includes `List-Unsubscribe` and `List-Unsubscribe-Post` headers. Unsubscribe links expire after 365 days. A new form submission cannot clear suppression; only a fresh confirmation can.
- The owner-only CSV export includes only confirmed, unsuppressed records. The admin waitlist view shows pending, confirmed, unsubscribed and legacy-unconfirmed states.
- Application SMTP errors do not log recipients, subjects, message bodies or bearer URLs. The Docker command disables Uvicorn access logs because URL query strings contain tokens. Hosting edge and email-provider logs remain outside application control; configure their retention and access separately.

## Operational limitations

- There is no campaign scheduler or product-update composition UI. Marketing remains disabled by default; this branch does not send a campaign.
- One-click unsubscribe links use a GET action for ordinary email readers and an RFC 8058 POST action for clients that support it. Some mail security scanners may follow a GET link before a person does, causing an unwanted suppression. Such a suppression is privacy-preserving and can be reversed only through a fresh opt-in.
- SMTP acceptance is not proof of inbox delivery. If an exception occurs after remote acceptance, the first confirmation link remains usable; requesting a fresh one invalidates the first. Rate limits and a per-address resend interval reduce abuse, but provider-level deliverability and bounced-address handling still need operating procedures.
- The token secret must remain stable across deploys for outstanding links to work. Rotation intentionally invalidates them. Expired and used token rows are pruned opportunistically when a new token is issued; a scheduled retention job remains future work.
