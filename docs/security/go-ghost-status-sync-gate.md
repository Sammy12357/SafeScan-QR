# Go Ghost status sync release gate

The Phase 1 server foundation is **disabled**. `/api/go-ghost/status`, its
write route, subject creation, and consent writes return HTTP 503. The
`GO_GHOST_STATUS_SYNC_AVAILABLE` constant is `False` in source and cannot be
changed by an environment variable. Startup does not create the three new
status tables. There is no status sync, email reminder, extension
authentication, or server-side broker automation in this phase.

The internal schema initializer and data functions support development and
tests only. They store a random subject ID, self/family relationship, versioned
consent and family-authority timestamps, broker ID, bounded progress codes,
revision, and server timestamps. They never store a person's profile, a broker
listing URL, or free-form failure text. One action group may cover multiple
brands, but progress is keyed by **broker ID**. Family subjects cannot update
the PeopleConnect brands because those opt-outs require self-submission.

Client events are claims. `recheck_absent` becomes
`client_recheck_absent`; no client event can create an independently verified
removal. The page's draft `go-ghost-state.js` still uses
`verified_removed` for a client recheck and must be aligned before sync is
enabled. `confirmed_at` likewise records a client-reported confirmation.
Client timestamps are ignored; an expected server revision is required for
each update. Device progress must not be automatically uploaded from an
unowned or older `localStorage` entry after sign-in.

Before enabling any route:

1. Confirm every signed-in session resolves to one stable canonical user ID.
   Auth0 tenant connection settings and the identity migration still need
   review. The API must derive the owner from the session, never from JSON.
2. Add and test a stable, session-bound CSRF token for cookie-authenticated
   writes, including requests without an `Origin` header. Apply strict
   same-origin policy. Do not treat CORS or SameSite alone as CSRF protection.
3. Replace the current unbounded in-memory `RATE_LIMITS` path for these routes
   with a bounded account-keyed limiter. Cap subjects per account and writes
   per hour. Do not use a user-provided subject ID as the limiter key.
4. Design separate extension authentication. A browser extension must not
   acquire or reuse a website session cookie, and `source=extension` must not
   be trusted from a JSON field. Until then, only a manually authenticated web
   route may call the data layer.
5. Finalize the consent text and its version, including the family attestation
   wording. The current `go-ghost-draft-1` version is not launch consent.
6. Verify the Render database uses a persistent disk. Run the schema migration
   only as part of the reviewed rollout. Exercise export and account erasure
   with both old and new tables, including the retired PII-bearing
   `go_ghost_removal_jobs` table.
7. Align status wording and client/server transitions. A user or extension
   report of an absent listing cannot be presented as independent proof of
   removal. Add an audit event with only broker ID and bounded state code;
   avoid request IP, user agent, subject profile, and free-form metadata.
8. Add a real follow-up scheduler only after email opt-in, unsubscribe, and
   delivery controls are designed and tested. The current due timestamp is
   stored for future UI use only; it does not trigger email.

The data layer requires explicit `user_id` predicates even for admins; the
general SQLite RLS helper deliberately bypasses owner filtering for admin and
owner roles. The privacy export/deletion functions detect absent status
tables, so the existing production legal flows still work while the feature
is off.
