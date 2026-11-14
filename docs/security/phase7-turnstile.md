# Phase 7: public-form bot checks

Cloudflare Turnstile protects guest URL reports, guest privacy requests, and
the waitlist form. Authenticated privacy requests keep the existing session and
receive per-account and per-IP limits. All privacy requests, including guest
ones, also have a separate 10-per-hour IP limit before database lookup or
email. The process-local rate-limit store is bounded, but its budgets reset on
restart and are independent across workers; use a shared store before scaling
past one Render worker.

The server calls [Siteverify](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
for each guest submission. It accepts only `success: true` with the exact
expected action (`url_report`, `data_request`, or `waitlist`) and a hostname
matching the incoming, allowlisted public host. It fails closed for a missing,
expired, reused, malformed, or mismatched token, provider timeout, and missing
configuration. It does not send visitor IPs to Cloudflare. Cloudflare tokens
expire after five minutes and are single use. The client resets the report
widget after submission; browser forms receive Turnstile's automatic hidden
`cf-turnstile-response` field.

## Render configuration and release gate

1. In Cloudflare Turnstile, create a widget permitting **each public hostname**
   that will serve these forms, for example `sqafe.com` and
   `safescan-qr.onrender.com`. Add `www.sqafe.com` only if that host actually
   serves the site. Do not enter a URL scheme or path.
2. In the Render web service's **Environment** settings, set
   `TURNSTILE_SITE_KEY` to the public site key, `TURNSTILE_SECRET_KEY` to the
   private secret, and `TURNSTILE_HOSTNAMES` to the matching comma-separated
   hostnames. Keep `TURNSTILE_ENABLED=false` until all three are set. The
   enable switch adds Cloudflare to the page's `script-src` and `frame-src`
   [CSP directives](https://developers.cloudflare.com/turnstile/reference/content-security-policy/).
3. Test a real widget on a non-production hostname that has been registered in
   the Cloudflare widget. Verify guest report, data-request, opt-out, and
   waitlist submissions, then check that a missing token and a used token are
   rejected. Check the browser console for CSP errors and that the normal form
   state is usable on mobile.
4. Only after the live-key check passes, set `TURNSTILE_ENABLED=true` in Render
   and deploy. Verify each public hostname; the app rejects a host absent from
   `TURNSTILE_HOSTNAMES`. If the Cloudflare service is unavailable, protected
   guest submissions return an error and can be retried later. To disable the
   check deliberately during an incident, set `TURNSTILE_ENABLED=false` and
   redeploy; rate limits still apply.

Cloudflare's [test keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
return `example.com` and no action in Siteverify, so they cannot exercise the
hostname/action-bound production verifier end to end. The automated tests
mock Siteverify, and a real-key staging check is a release gate.

The [explicit widget script](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/)
is shared by the report modal and all forms. It uses `appearance:
"interaction-only"` to keep the existing layout visually quiet unless
Cloudflare requires a challenge. Any browser extension blocking Turnstile
leaves the guest submission blocked until the user allows the challenge.

## Static-analysis baseline review

The Phase 7 route import shifts 18 existing `markupsafe.Markup(...)` calls in
`hackabull/routes_pages.py` by one line. Comparing the prior revision with
this change shows the 18 call expressions are identical, and Bandit still
reports the same 26 medium/high findings across the repository (18 B704
calls and eight B608 SQL construction findings). Their surrounding-code
digests changed because the exact baseline includes line context. The
`.github/security/bandit-baseline.json` entries were refreshed only after
that comparison. See [the Phase 4 B704 review](phase4-bandit-review.md)
for the underlying output-encoding rationale.
