# Public component API budget

The four standalone component routes (`check-reputation`, `trace-redirects`,
`check-domain`, and `check-crypto-patterns`) share 10 requests per client per
rolling hour. Reputation and redirect checks also share a tighter five-call
outbound budget per client. All four routes share a 120-call hourly cap per
worker; outbound routes share a 60-call hourly cap per worker. A rejected call
returns HTTP 429 with `Retry-After` before validation or provider work.

The in-memory store keeps at most 4,096 hashed client keys and contains no
URLs, QR payloads, or raw IP addresses. It resets on deploy and is not a
cross-worker quota. Main still accepts a spoofable forwarded IP; the global
cap is the backstop until the Phase 3 trusted-ingress migration is released.
Do not raise these caps or scale to multiple workers before that migration.
The website has no callers of these component routes; the mobile app exports
helpers for them but normal scans call `/api/analyze` or `/api/scan`. Exhausting
the shared component cap can deny other component calls, but not normal scans.

This change does not impose a monthly Web Risk billing cap. The Phase 7
provider-budget draft owns that release gate. The production Web Risk key is
currently absent, so Google reputation remains unverified until the owner
configures a licensed key and completes the provider-budget release.
