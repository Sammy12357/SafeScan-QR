# Phase 3 request-budget preparation

The in-process sliding-window store keeps at most 4,096 buckets. It removes
expired buckets opportunistically and evicts the least recently used bucket
at capacity. This bounds memory even when clients present many distinct IPs.
Each bucket holds only timestamps from its current window. Requests that have
both an account identity and an IP check both budgets atomically. The account
limit remains the route's existing limit; the IP budget defaults to the greater
of 100 or ten times that limit so multiple users on one network do not share
a 30-scan account quota. Call sites can pass `ip_limit` when a route needs a
specific shared-IP ceiling. A rejection returns 429 with `Retry-After`.

The Phase 3 route presets are: login 5/min/IP shared across Google, mobile,
and local entry points, plus 10/15 min/account after a provider token is
verified (or by normalized email for local login); register 3/hr/IP;
signed-in text and file API scans together 30/hr/account; guest HTML and JSON scans together
10/hr/IP; consent 10/hr/IP; waitlist 3/hr/IP and 1/day/normalized address;
reports 10/hr/IP; and Go Ghost 3/day/account. Mobile and JSON API 429s retain
JSON responses. Browser form endpoints return a small HTML 429 page, also with
`Retry-After`, so form navigation does not land on raw JSON.

Local email/password registration and login routes are disabled in production
by `LOCAL_AUTH_ENABLED` and return 404 there. Their quotas protect only local
developer and test runtimes where those routes are deliberately enabled.

This is still **per process**. Multiple Render workers do not share the
window, and an LRU eviction can reset a bucket under sustained high-cardinality
traffic. A shared Redis or SQLite-backed budget is required for a global limit.
The owner chose this bounded in-memory design for the current release. The
limits are therefore best-effort per worker, not a global account or IP
guarantee; operations should revisit shared storage if worker count or abuse
volume grows.
The client-IP resolver is included in this branch, but its production ingress
assumption remains provisional until the separate Render diagnostic verifies
both public hostnames from two networks. Camera upload budgets use that IP
identity as an IP budget, preserving their existing 90-per-15-minute limit.
Keep this branch out of production until the ingress check is complete; see
`docs/security/phase-3-release.md`.

Prometheus path labels now use the FastAPI route template after routing, or
`unmatched` when no route matched. A 10,000-path regression verifies that
random 404 paths produce one path label.
