# Phase 8 production secret gate

Before merging Phase 8, create or confirm these values in Render Environment:

| Setting | Source |
| --- | --- |
| `PRIVACY_HASH_SALT` | Generate a stable random value of at least 32 bytes. Keep it across redeploys so IP hashes remain comparable. |
| `STRIPE_WEBHOOK_SECRET` | Copy the active Stripe endpoint's `whsec_` signing secret; do not use the Payment Link URL. |
| `METRICS_TOKEN` | Generate a random value of at least 32 bytes. The metrics scraper sends it as `Authorization: Bearer …`. |
| `CSRF_SECRET` | Generate a separate stable random value of at least 32 bytes. |

For self-generated values, `python -c 'import secrets; print(secrets.token_urlsafe(32))'`
uses 32 random bytes. Do not copy the generated value into source control or
logs. The startup check names missing or clearly weak settings but cannot
prove that an arbitrary long value was generated securely. It runs before
background jobs begin. A failed check prevents the web process from becoming
ready; this is an intentional release gate, so prepare Render first.

CSRF tokens are HMACs of the active browser session or anonymous browser
secret, keyed by `CSRF_SECRET`. Changing `CSRF_SECRET` invalidates forms
already open in browsers; users can reload the page. The design follows the
[OWASP signed token guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
The generation command uses Python's documented
[`secrets.token_urlsafe`](https://docs.python.org/3/library/secrets.html).
