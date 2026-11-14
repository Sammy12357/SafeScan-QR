# Phase 4 output and consent behavior

- Legal and admin HTML templates escape dynamic values. The privacy policy's configured contact email is escaped before the server-authored HTML is marked safe.
- The banner offers two server-supported choices: optional anonymous scanner counts on (`all`) or off (`essential_only`). “Manage Preferences” opens that one setting. The browser saves a choice only after `/api/consent` confirms it.
- A verified `revoke_consent` request writes an opt-out for the signed-in account and switches the current browser to `essential_only`. A mismatched email or anonymous request remains in `data_requests` with `submitted` status without changing another account's opt-out.
- Scanner performance counts deliberately omit account cookies and device identifiers. Therefore the server cannot associate a count from a second browser with an account revocation. Cross-device synchronization would require an explicit account-aware consent design and a separate privacy review.

Integration: preserve Phase 2's rule that visiting `/pay/alpha/success` never activates a subscription. The Phase 4 autoescaped partial must show a pending confirmation state after those branches merge. The CSRF branch supplies a token to the direct data-request form and other browser POST forms.
