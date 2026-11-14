# Go Ghost browser release gate

The public web service does not run Go Ghost broker automation. The API returns
`503` after authentication and before importing the removal engine or creating a
job. The page keeps Search, Opt out, Copy details, and manual progress tracking.
The manual Opt out action opens the broker's published URL without appending
personal details to its query string.

`GO_GHOST_BROWSER_AUTOMATION_AVAILABLE` is deliberately fixed to `False` and has
no environment-variable override. Do not enable same-container Chromium on
Render Starter. The current engine launches Chromium with `--no-sandbox` and
third-party pages can navigate or request network destinations outside their
starting broker domain, including private addresses reachable from the app.

Before enabling assisted submissions, move browser work to an isolated service
without access to SafeScan's database or application secrets. Enforce outbound
network policy outside the browser process: deny loopback, private/link-local,
metadata, and internal service ranges; permit only the broker destinations
needed for each step, including redirects and subresources. Run Chromium under
a supported user/seccomp sandbox, keep the broker allowlist, bound job time and
concurrency, and return only bounded, sanitized status values. Verify these
controls with integration tests that attempt DNS rebinding, redirects, and
subresource requests to denied addresses. A browser request interceptor alone
is not a network isolation boundary.
