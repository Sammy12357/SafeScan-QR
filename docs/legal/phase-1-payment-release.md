# Phase 1 payment release gate

Prepared 2026-11-15. This branch is a code change, not an assertion that the live Stripe account or legal text has been verified. Card checkout stays disabled unless all required settings are supplied.

## Render settings and owner checks

1. Set `APP_URL=https://sqafe.com`, `STRIPE_SECRET_KEY` (the matching test or live secret key), `STRIPE_ALPHA_PRICE_ID`, `STRIPE_ALPHA_PRODUCT_ID`, and `STRIPE_WEBHOOK_SECRET`. The Price must be active, US$1, USD, monthly, one unit, and belong to that Product; the server rechecks it with Stripe before every Checkout Session. No key belongs in Git or a browser URL.
2. Set the verified business identity: `BILLING_LEGAL_ENTITY_NAME`, `BILLING_POSTAL_ADDRESS`, and `BILLING_SUPPORT_EMAIL`. Card and Solana checkout stay closed without them.
3. The owner chose the proposed refund text: “Payments are not refunded after a billing period starts, except where required by law.” It is the default `BILLING_REFUND_POLICY_TEXT`; counsel should review it for the places SafeScan sells. Change the setting if approved wording differs. `BILLING_TERMS_VERSION` defaults to `2026-11-alpha-v1`; increment it whenever displayed terms change.
4. Configure SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `EMAIL_FROM`) and test receipt delivery. The app sends a confirmation containing the saved recurring terms, seller identity, and a signed-in management path after a verified purchase. Checkout stays closed when SMTP is not configured.
5. In Stripe, set the public business information and Terms URL, confirm Checkout's required Terms acceptance, enable the customer portal **subscription cancellation**, configure billing/invoice email and receipts, confirm tax handling, and test the portal in the matching Stripe mode. Only then set `STRIPE_BILLING_SETTINGS_CONFIRMED=true`. This flag is an owner attestation; code cannot inspect all dashboard settings.
6. Configure the webhook endpoint `https://sqafe.com/webhooks/stripe` for `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`, and `invoice.paid`. Test delivery and a real test-mode cancel before switching to live credentials. Use the signing secret from that endpoint, not the Stripe API key.
7. Disable the old `buy.stripe.com` Payment Link. New access requires a locally created, account-bound Checkout Session. A legacy Payment Link may still charge someone without creating a SafeScan entitlement.

## Migration and review

- Existing Stripe rows without the new `stripe_verified_at` proof are marked `unverified` at schema initialization. This can interrupt legitimate older purchases. Reconcile affected customers against Stripe's customer and subscription records; do not link by email alone. Existing unverified rows cannot open another customer's portal.
- The new `stripe_checkout_intents` table retains user ID, email, a snapshot of consent and refund text, version, and Stripe Session ID. Include these fields in the privacy inventory, access export, deletion/retention procedure, and incident response plan. Payment and consent records may need a lawful retention period even after account deletion; counsel should decide it before live release.
- The owner/attorney should sign off on the subscription terms, tax, refund exceptions, business identity, and acknowledgement wording. Test the checkout and cancellation flow on an iPhone as well as desktop.
- The age-gate branch must replace `payments_stripe.require_payment_user` with the shared authenticated 18+ helper. This hook is used by new card Checkout and Solana verification; the payment page also calls it for signed-in users. Keep the signed-in **manage/cancel** route accessible regardless of age-gate status so an existing payer can cancel.

Stripe references: [Checkout Session creation](https://docs.stripe.com/api/checkout/sessions/create), [Price object](https://docs.stripe.com/api/prices/object), [customer portal sessions](https://docs.stripe.com/api/customer_portal/sessions/create), [portal cancellation configuration](https://docs.stripe.com/api/customer_portal/configurations/create), [server-side post-payment events](https://docs.stripe.com/payments/existing-customers), [webhook signatures](https://docs.stripe.com/webhooks/signature).
