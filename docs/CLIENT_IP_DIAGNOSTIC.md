# Temporary client IP ingress check

This is a temporary check for the F3 client IP hardening change. It reveals only
stable HMAC fingerprints and header presence/validity to an authenticated owner.
It never returns or logs raw client IPs or forwarding header values.

## Enable after Phase 1

Set these Render environment variables on the SafeScan web service only when
ready to run the comparison:

```text
CLIENT_IP_DIAGNOSTIC_ENABLED=true
CLIENT_IP_DIAGNOSTIC_HMAC_KEY=<fresh random value of at least 32 bytes>
```

Keep the key stable during the comparison. The endpoint remains a 404 unless
the service is on Render, both settings are valid, and the requester is signed
in as an owner. It is excluded from OpenAPI and sends `Cache-Control: no-store`.

## Compare

1. Sign in as an owner on two devices using **different networks** (for
   example, computer on Wi-Fi and iPhone on cellular). If they share one NAT,
   matching fingerprints would be expected and would not prove aggregation.
2. On each device, open `/admin/debug/client-ip` on both `https://sqafe.com`
   and `https://safescan-qr.onrender.com` after signing in on each hostname.
3. Record only the fingerprints and boolean fields. For each device,
   `edgeFingerprint` should remain stable between its two hostnames. Across
   the two different networks, `edgeFingerprint` should differ. All responses
   should say `edgeHeaderPresent`, `edgeHeaderSingle`, and `edgeHeaderValid` are
   true. A mismatch between `edgeFingerprint` and `resolvedFingerprint` is
   expected before F3 because the current resolver uses X-Forwarded-For.
4. If distinct networks yield the same edge fingerprint on `sqafe.com`, stop
   the F3 rollout and examine the Cloudflare Orange-to-Orange ingress. Do not
   treat X-Forwarded-For or True-Client-IP as a trusted workaround.

The probe only shows what reached the application; it does not itself prove
that an upstream header cannot be forged. Render documents its public edge's
overwrite behavior: <https://render.com/articles/host-pocketbase-on-render>.

## Remove

Immediately after collecting the comparison, set
`CLIENT_IP_DIAGNOSTIC_ENABLED=false` and delete
`CLIENT_IP_DIAGNOSTIC_HMAC_KEY` from Render. Then submit a removal PR deleting
`hackabull/ip_diagnostic.py`, its `/admin/debug/client-ip` route, the tests,
this document, and the CI test-list entry. Merge that removal before treating
F3 as complete.
