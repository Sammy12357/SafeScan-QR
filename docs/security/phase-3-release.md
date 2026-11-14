# Phase 3 release preflight

This branch combines the client-IP resolver, bounded request budgets, metrics
path labels, legacy verdict-cache removal, and private HTML caching. It is
prepared for review, **not** ready for production until the ingress check is
complete.

1. Deploy the separate temporary, owner-only [client-IP diagnostic PR
   #35](https://github.com/Sammy12357/SafeScan-QR/pull/35) first. It is inert
   until its Render feature flag and HMAC key are configured. Follow its
   `docs/CLIENT_IP_DIAGNOSTIC.md` plan on two different networks (for example,
   Wi-Fi and iPhone cellular) on both `sqafe.com` and the Render hostname.
   Compare only the HMAC fingerprints; do not paste raw IPs or header values
   into issues. If the two networks collapse to one edge fingerprint or the
   public paths disagree, resolve that ingress behavior before merging this
   branch. Remove the temporary route and settings after the comparison.
2. Confirm the production Uvicorn command can use `--no-proxy-headers` so the
   socket-peer fallback cannot be rewritten by a forwarded header. The
   resolver trusts only Render's validated, edge-authored
   `CF-Connecting-IP`; missing or malformed values share an unverified-ingress
   rate-limit bucket.
3. Check `WEB_CONCURRENCY` and document the operational rate-limit guarantee.
   The 4,096-bucket store is process-local: multiple workers do not share a
   budget, and eviction can reset a bucket under high-cardinality traffic.
   A shared Redis or SQLite budget is needed before claiming a global limit.
4. Verify a signed-in scan and a guest camera upload on both hostnames, then
   confirm dynamic HTML has `Cache-Control: private, no-store` and
   `Vary: Cookie`. The legacy `scan_results` shortcut is gone; the public
   pipeline's risk scoring and verdict logic are unchanged.

The ingress diagnostic is a release gate, and this branch has not changed
Render configuration or been deployed.
