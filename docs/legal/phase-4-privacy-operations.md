# Privacy operations: Phase 4 implementation status

**ATTORNEY REVIEW NEEDED.** This is an engineering record, not an approved privacy notice. The field-level map, billing retention, data-rights automation and public policy reconciliation remain open.

## Changes in this branch

- New web scan history, scan-event references, recent-scan counters and fraud references keep the URL scheme, host and path, but drop query and fragment. This can collapse two URLs that differ only by query into one unique scan. The immediate scan response and security checks still use the full input URL.
- The result cache uses a keyed HMAC of the full URL so lookup remains exact without storing the URL. Old raw-URL cache rows are purged on schema initialization; cached results older than 24 hours are deleted.
- A startup scrub removes old query-bearing or private payload references from scan history, scan events, aggregate scan URL lists and velocity rows. It keeps aggregate scan counts. Existing scan events with a raw query are discarded, so a later scan can create a new event. The scrub is idempotent; it does not erase SQLite pages or backups already made before the deployment. Those require a storage/backups retention review.
- Consent-log rows older than five calendar years are deleted at startup and daily. The five-year period is already stated in the current public policy; it is not a conclusion about a legal requirement. Set `RETENTION_LEGAL_HOLD=true` during a documented investigation to pause this deletion. This flag does not stop disposable cache expiry.

## Unfinished data rights and retention work

- The current `/legal/data-request` export and deletion cover only a subset of user-bound tables. They **must not** be described as complete. Deleting an account while a verified Stripe subscription is active risks leaving billing running; Phase 1's account-erasure guard must be integrated first. Counsel must decide whether to retain or anonymize billing consents, receipts, fraud evidence and audit trails after a request.
- The public policy says inactive accounts are deleted after two years, but there is no safe account-deletion scheduler. Do not add one until active subscriptions, wallet and Go Ghost records, legal holds, backups and identity verification are resolved. Revise the public promise with an archived version and attorney review if the job cannot be delivered.
- `docs/legal/data-map.yaml` is a schema-level inventory. Its table-wide source, purpose, recipient and retention descriptions do not identify every field's legal basis or exact retention. It is not yet suitable as the single source for the public policy or admin processing log. The table/column drift test must remain green as fields are added.
- `url_reports`, public blocklist entries, other users' referral rows, fraud metadata and historic backups may still contain query strings or personal details. They need separate evidence and ownership rules. The listing dispute phase should handle reported URLs without overbroad blocklist matching.
- A 45-day target can be shown to admins after the owner and counsel choose which request categories and jurisdictions use it. Do not present it as a universal deadline. Requests from unauthenticated email addresses remain pending; an email match alone is not ownership proof.
- Data sent to Google Web Risk includes a scanned URL's full query when configured; the PhishTank feed is checked locally. A query can contain personal tokens. A provider-by-provider disclosure and contractual review are needed before a public privacy-table revision. See `docs/legal/vendor-register.md`.

## Phase 1 integration notes

When rebasing on Phase 1, add `stripe_checkout_intents`, `stripe_webhook_events`, `payment_form_tokens`, `age_eligibility`, pending age/denial tables, email token/suppression tables and new cookies to the data/storage inventories. Keep `tests/test_legal_data_map.py` green. Never automatically erase an active verified subscriber to satisfy an account deletion request; the user must retain a reachable cancellation path. See `docs/legal/phase-1-payment-release.md` in Phase 1.
