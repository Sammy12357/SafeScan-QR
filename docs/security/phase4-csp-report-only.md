# Phase 4 CSP report-only probe

`CSP_REPORT_ONLY_ENABLED=false` is the default. When explicitly enabled, 200
HTML responses add a second CSP that tests `style-src` without
`'unsafe-inline'`. The enforced CSP is unchanged. The probe also adds
`Reporting-Endpoints` plus `report-to` for modern browsers and `report-uri`
for the older reporting path. Both point to the same-origin
`/api/security/csp-report` receiver. The receiver returns 404 while the flag
is off.

The receiver accepts only legacy `application/csp-report` and modern
`application/reports+json`. It reads at most 8 KiB over three seconds, accepts
up to 16 reports per request, and admits at most 300 reports per minute per
worker. Its only retained data is that one-minute queue of count timestamps.
The Prometheus metric `safescan_csp_reports_total` has exactly four possible
directive labels: `style-src`, `style-src-attr`, `style-src-elem`, and `other`.
It does not store document URLs, blocked URLs, samples, report bodies, account
IDs, session IDs, or IP addresses. The path bypasses the ordinary IP-linked
audit limiter and account lookup. Browser reports are untrusted and can be
forged, so counts guide investigation; they do not prove an attack.

After the earlier identity and ingress release gates are complete, enable the
flag for a limited measurement period and inspect aggregate counts alongside
real-browser DevTools on both public hostnames. Keep the probe on for a week
before deciding whether inline styles can be removed from the enforced policy.
Do not make that enforcement change solely from counts: they intentionally do
not identify the offending page or element. Turn the flag off after the
measurement; turning it off stops both the report-only header and receiver.

The policy and delivery formats follow the [W3C CSP3 reporting section](https://www.w3.org/TR/CSP3/#violation-reports) and the [W3C Reporting API](https://www.w3.org/TR/reporting-1/).
