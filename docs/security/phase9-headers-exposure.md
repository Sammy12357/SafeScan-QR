# Phase 9: public exposure and response headers

Production (`RENDER` or `ENVIRONMENT=production`) no longer serves FastAPI's
`/docs`, `/redoc`, or `/openapi.json`. Development still serves them.
[FastAPI documents `openapi_url=None` as the switch that disables the schema
and its documentation UIs](https://fastapi.tiangolo.com/tutorial/metadata/).

The public `/health`, `/health/live`, `/health/ready`, `/health/providers`, and
`/api/health` responses now contain only a status field. An exception in the
readiness or provider probe returns HTTP 503 without database paths, exception text, or
provider configuration. Public probes do not set a guest CSRF cookie or
restore a remembered session.

Responses carry `Cross-Origin-Resource-Policy: same-origin` and
`X-Permitted-Cross-Domain-Policies: none`. `Cross-Origin-Opener-Policy` is
`same-origin` except on `/`, `/test-site`, and `/login`, where Google Identity
Services is loaded and the value is `same-origin-allow-popups`. [Google's web
sign-in guide](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid)
warns that popup communication can fail without that value when FedCM is
unavailable; [Chrome's security guidance](https://developer.chrome.com/docs/modern-web-guidance/guides/security/security)
also recommends checking OAuth and payment popup flows before adopting strict
COOP. CORP protects app responses from cross-origin `no-cors` embedding; it
does not replace the existing exact-origin CORS allowlist. The legacy
cross-domain header follows [OWASP's secure-header guidance](https://secure-headers-project.owasp.org/best-practices/).

The [Permissions Policy syntax](https://developer.chrome.com/docs/privacy-security/permissions-policy)
explicitly permits same-origin camera access for the QR scanner and
same-origin clipboard write for the copy action. It disables unused device
APIs and `browsing-topics`, the current Topics API directive. The retired
`interest-cohort` directive was not added. The policy leaves FedCM, Spline
fullscreen/autoplay, and Turnstile features unrestricted so those existing
flows can continue to work.

## Vulnerability contact

`/.well-known/security.txt` uses `safescanqr@gmail.com`, the contact already
published in `SECURITY.md`, and expires at `2027-05-01T00:00:00Z`. It omits
`Canonical` because the same application can be reached through `sqafe.com`
and the Render hostname. [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html)
requires `Contact` and `Expires` and warns that a Canonical field must include
the URL used to retrieve the file. The Docker image includes the file.

Before release, confirm that the mailbox is monitored for vulnerability
reports and that the expiry is renewed before May 2027. In a real browser,
check Google sign-in and One Tap on home/login, camera access on iPhone Safari,
copying a QR result, Turnstile, and any intentional cross-origin embedding of
SafeScan assets. Verify the production routes and headers on both public
hostnames. This branch contains no production deployment.
