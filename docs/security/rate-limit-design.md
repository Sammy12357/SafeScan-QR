# Phase 3 request-budget preparation

The in-process sliding-window store keeps at most 4,096 buckets. It removes
expired buckets opportunistically and evicts the least recently used bucket
at capacity. This bounds memory even when clients present many distinct IPs.
Each bucket holds only timestamps from its current window. Requests that have
both an account identity and an IP check both budgets atomically. The account
limit remains the route's existing limit; the IP budget defaults to the greater
of 100 or ten times that limit so multiple users on one network do not share
a 30-scan account quota. Call sites can pass `ip_limit` when a route needs a
specific shared-IP ceiling. A rejection keeps the existing JSON response and
`Retry-After` header.

This is still **per process**. Multiple Render workers do not share the
window, and an LRU eviction can reset a bucket under sustained high-cardinality
traffic. A shared Redis or SQLite-backed budget is required for a global limit.
The IP identity also remains provisional until the separate Render ingress
diagnostic validates the planned client-IP resolver. Keep this preparation
out of production until Phase 3's ingress check is complete.

Prometheus path labels now use the FastAPI route template after routing, or
`unmatched` when no route matched. A 10,000-path regression verifies that
random 404 paths produce one path label.
