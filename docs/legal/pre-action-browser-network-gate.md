# Pre-action browser network gate

The accessibility CI job also checks browser requests made while each page in
`scripts/legal_accessibility_audit.py` loads in dark and light themes, before
the test performs any click or form submission. Guest views start without a
saved consent choice; the inventory also includes synthetic member views. All
third-party HTTP(S) and WebSocket requests are blocked locally, but
the audit records each attempted request first and fails CI if any unexpected
destination appears. The only exception is the Google Identity Services
`https://accounts.google.com/gsi/client` **script** on `/login`; the audit
blocks even that script from reaching Google.

The report stores the page name and path, theme, request resource type and
destination **origin**. It deliberately omits the destination path, query and
fragment, which may contain credentials or personal data. A browser regression
test injects a tracking image and a WebSocket with secret query values and
verifies that both attempts are detected without logging those values.

Run locally with the development dependencies and Chromium installed:

```sh
SAFESCAN_REQUIRE_BROWSER=1 python -m pytest tests/test_legal_network_gate.py -q
python scripts/legal_accessibility_audit.py
```

This checks the local mock-mode app and its listed page-load states. It does
not verify production configuration, real account profile pictures, traffic
after a user action, browser extensions, or server-side provider calls. Review
those separately before making a claim about live traffic. New public HTML GET
routes must be added to the audit inventory; the existing route-inventory
check fails if one is omitted.
