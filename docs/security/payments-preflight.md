# Alpha payment hardening preflight

Prepared 2026-11-14. This branch is Phase 2 preparation and must be merged only after the supply-chain phase and the identity migration review.

## Before release

1. In the [Stripe Dashboard Payment Links page](https://dashboard.stripe.com/payment-links), select the existing SafeScan Alpha link by matching its `buy.stripe.com` URL. Open **Workbench → Webhooks → SafeScan endpoint → Event deliveries**, select a `checkout.session.completed` delivery for that link, and read `data.object.payment_link` in the signed event payload. That is the **Payment Link object ID** (`plink_...`); the `buy.stripe.com` URL path is not the ID. If no prior delivery exists, use the [Payment Links API](https://docs.stripe.com/api/payment_links/list) to match the object's `url` and read its `id`. Set `ALPHA_STRIPE_PAYMENT_LINK_ID` in Render before deploying this code. The app checks the signed Checkout Session's `payment_link`, `mode`, `payment_status`, positive amount, and subscription ID. If the ID is missing, checkout webhooks return 503 so Stripe can retry after configuration. See [Stripe's Checkout Session fields](https://docs.stripe.com/api/checkout/sessions/object) and [webhook retry guidance](https://docs.stripe.com/webhooks).
2. Confirm the Stripe webhook endpoint uses the correct `STRIPE_WEBHOOK_SECRET`, and its enabled event types include `checkout.session.completed`, `checkout.session.async_payment_succeeded`, `invoice.paid`, `customer.subscription.updated`, and `customer.subscription.deleted`.
3. On an **offline SQLite backup**, count legacy success-page subscriptions and duplicate Solana signatures before deployment:

   ```sql
   SELECT COUNT(*) FROM alpha_subscriptions
     WHERE provider = 'stripe' AND status = 'active' AND checkout_session_id IS NULL;
   SELECT COUNT(*) FROM (
     SELECT signature FROM alpha_solana_payment_references
     WHERE signature IS NOT NULL GROUP BY signature HAVING COUNT(*) > 1
   );
   ```

   The new unique index on Solana signatures will reject an existing database with duplicates. Review any such rows privately before the migration. Legacy success-page rows remain in the database; `has_active_alpha()` deliberately excludes them because no verified Stripe payment is attached.
4. Use a Stripe test payment and a distinct Solana test transaction to verify activation, replay behavior, cancellation, and expiry. Do not use a public production payment as a test.

## Processing behavior

- A success-page visit is informational and writes no subscription.
- A guest sees a sign-in link before card checkout so the resulting Checkout Session has an account reference. A paid event without a valid account reference is recorded as `unmatched` in `stripe_events` for manual review; customer email never chooses an account.
- The `stripe_events` ledger stores event IDs and a limited outcome. It does not store the raw webhook payload. Duplicate event IDs and one-time object/type pairs are ignored atomically with the subscription update. `customer.subscription.updated` can recur for the same object, so it is deduplicated only by event ID.
- Only a finalized Solana transaction can activate a quote. The database allows a signature to be claimed once.
- `has_active_alpha()` requires a webhook-sourced Stripe row with `status='active'` and a future `expires_at`. A paid invoice with a positive amount establishes that period, including when the period is present only on modern invoice lines. Stripe can settle in a customer's local currency, so the configured Payment Link and subscription ID bind the product instead of a USD-only check. Subscription updates do not extend access before payment. The helper is prepared for future feature gates and is not yet used by the site.

Stripe recommends event-ID and object/type deduplication, a five-minute signature window, and handling delayed Checkout payments through `async_payment_succeeded`: [webhook guidance](https://docs.stripe.com/webhooks), [Checkout fulfillment](https://docs.stripe.com/payments/existing-customers?platform=web&ui=stripe-hosted). Solana documents the `finalized` commitment on [`getSignaturesForAddress`](https://solana.com/docs/rpc/http/getsignaturesforaddress) and [`getTransaction`](https://solana.com/docs/rpc/http/gettransaction).

## Remaining operational limitation

Stripe may deliver invoice or subscription events before the related Checkout event. Such events are recorded as `unmatched` and need review in the Stripe Dashboard; the app does not infer identity from email or blindly retry activation. Before using `has_active_alpha()` as a feature gate, add a reconciliation job that fetches the current subscription and invoice state from Stripe and verifies the configured price. This also handles missed webhook deliveries and out-of-order lifecycle events.
