# QR URL listing review and correction — Phase 5

**Engineering workflow; attorney and owner review required before treating it as a legal policy.** The public page at `/malicious-database/policy` describes the current application behavior in plain language. It does not promise that SafeScan can determine whether a business or every page on a domain is malicious.

## Publication boundary

- The public API continues to publish only apex DNS domains from active administrator blocklist rows. It never publishes paths, query strings, reporter identities, scan history, evidence notes, or dispute claims.
- A public entry describes an administrator URL record, its source category, and the recorded date. New entries with captured evidence say “Reviewed QR URL observation”; older entries say “Administrator listing record.” An entry can represent several URL records on one domain. The public ID is a hash of the domain and is not an internal blocklist ID.
- A public user report only creates a pending report. To publish a URL from a report or staff scan, the administrator must choose a review source and write a 20–500 character independent observation. The server stores the source, staff identity, source record ID, observation, and timestamp in `listing_evidence`.
- Pre-Phase-5 blocklist rows have only their original administrator record (`reason`, `added_by`, `created_at`); no independent provider result can be reconstructed. They are shown publicly as “SafeScan administrator listing record,” without claiming a provider match. **Owner and counsel should decide whether those legacy entries should remain visible pending re-review.**

## Dispute handling

1. The “Dispute this listing” link on every public card opens a domain-specific form. The server rechecks that the listing is active. The form requires a contact email and 20–2,000 character claim. It is capped at 8 KiB, has a honeypot, an IP rate limit of three attempts per hour, and a per-domain cap of ten submissions per day. The account is not required.
2. Submission stores the claim in `listing_disputes` and immediately marks that domain “Under review” in the public feed. It adds an item to `/admin/reports?tab=disputes`. If transactional SMTP is configured, a notification containing only the domain and admin queue link is sent to up to five admin addresses. The claim and contact email are never in that notification.
3. Staff should check the dispute queue at least each business day. The queue shows a first-review target of two business days, excluding weekends; holidays are not yet modeled. If SMTP is unavailable, staff must use the contact email in the protected detail page to respond manually. The app does not guarantee delivery or enforce the target automatically.
4. `/admin/listings/{id}` shows blocklist and evidence records plus the private claim. An administrator may add a fresh evidence record for a legacy entry, acknowledge review, retain with a written reason, or remove with a written reason. Retaining a disputed entry requires at least one current captured evidence record. A removal transaction soft-removes *all* active URL records behind the domain entry before returning, so the public entry disappears on the next uncached read. Evidence and dispute decisions remain available to staff for review.
5. The same-origin POST guard, staff role checks, parameterized SQL, and HTML escaping apply to review routes. Public API responses use `Cache-Control: no-store`. Admin action audit records contain the decision type and count removed, not claim/contact text.

## Open operational and legal decisions

- Counsel/security lead: define the required independent evidence standard, acceptable manual verification method, how long evidence and dispute contact details are retained, and whether legacy entries need temporary withdrawal.
- Owner: assign a named staff reviewer, review the queue daily, configure transactional mail or a manual response process, and monitor the two-business-day target. A first response is an operational commitment; the UI records first staff review, not verified delivery.
- Engineering: add a scheduled overdue alert and holiday calendar if the owner wants a measurable service-level commitment. The shared in-memory limiter now caps 4,096 active identity/bucket keys per process. At capacity it removes expired keys and returns 429 to new identities while active keys remain; it does not evict live limits. It resets on process restart, is not shared across workers, and relies on the deployment's proxy handling of client-IP headers. The database per-domain cap still applies. Use a shared rate-limit store and verify trusted proxy configuration before scaling.
- Privacy policy: include `listing_disputes` and `listing_evidence` in the reviewed retention and rights-request scope. The Phase 5 data map entries describe the fields but do not assert an approved retention period.
