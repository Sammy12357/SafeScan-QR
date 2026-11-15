# SafeScan QR Agent Instructions

## Agent skills

Project skills live under `.agents/skills/`. Use `safescan-ship` when preparing a website or backend release, `safescan-security-gate` for security-sensitive changes, `safescan-ui-states` for frontend work, `qr-decode-bench` for camera or decoder changes, `go-ghost-recipe` for broker workflows, and `safescan-legal-gate` for public claims, data, policies, email, billing, tokens, licenses, or listing disputes. Read a skill when its scope matches the task; the user's current instructions and verified code state take precedence over older plans.

## Legal change review

Use the PR checklist and `docs/legal/` registers to record new personal data, third-party hosts, public claims, email, dependencies, and legal-document versions. The Python gates in `tests/test_legal_gate_*.py` and `tests/test_legal_data_map.py` run in CI; the diff-aware legal-document check requires a new version, effective date, snapshot, change-log entry, and attorney-packet row. These are engineering checks, not legal approval. Keep unverified business identity, marketing email, card checkout, and token distribution disabled. Mark drafted public legal text **ATTORNEY REVIEW NEEDED** and obtain qualified review before treating it as approved.

## Repository Assignments

- Main website and Render backend: https://github.com/Sammy12357/SafeScan-QR/tree/main
- Mobile app: https://github.com/Sammy12357/SafeScan-QR-App

When the work is for the public website, FastAPI backend, Stripe payment pages, admin pages, templates, static assets, SQLite persistence, or Render deploy behavior, use the main website repository.

When the work is for the React Native or Expo mobile app, scanner app screens, mobile auth, mobile API client, mobile stores, or app release configuration, use the mobile app repository.

## Main Site Deployment To Render

Render deploys the main SafeScan site from the `main` branch of:

```text
https://github.com/Sammy12357/SafeScan-QR
```

To deploy a website or backend change:

1. Make the change in the main site repository.
2. Run the focused tests for the area changed.
3. Commit the change to `main` or merge a PR into `main`.
4. Push `main` to GitHub.
5. Check Render for an automatic deploy.
6. If Render does not start a deploy, open the Render service and run:

```text
Manual Deploy > Deploy latest commit
```

7. Verify the live health endpoint and public site at:

```text
https://sqafe.com/api/health
https://sqafe.com/
```

For billing changes, inspect `https://sqafe.com/pay/alpha` without initiating a real payment. Verify checkout, webhook, portal, and cancellation paths with isolated test fixtures. A checkout return page is not proof of payment.

## Important Render Settings

Production SQLite data must live on a Render persistent disk. See `DEPLOYMENT.md` for storage details.

Expected production database environment variables:

```text
DATA_DIR=/var/data
SQLITE_DB_PATH=/var/data/qr_cache.db
DATABASE_URL=sqlite:////var/data/qr_cache.db
```

Do not rely on `/app/data` unless a Render persistent disk is explicitly mounted there.

## Stripe Alpha Premium Notes

The old Stripe Payment Link must be disabled before card billing opens. The success page never grants access. New card subscriptions require an account-bound Checkout Session, recorded recurring consent, a verified Stripe webhook event, and the business and Stripe settings in `docs/legal/phase-1-payment-release.md`. The portal management path remains available to existing verified subscribers even if new checkout is closed.

## Test Commands

Use the bundled or local Python runtime available in the environment.

Focused verified billing tests (after installing the project test dependencies):

```text
python3 -m pytest tests/test_auth_persistence.py::test_stripe_checkout_webhook_receipt_portal_and_cancel tests/test_auth_persistence.py::test_stripe_rejects_bad_signatures_unpaid_and_wrong_product tests/test_auth_persistence.py::test_card_checkout_requires_verified_business_and_stripe_settings -q
```

Broader auth persistence suite:

```text
python3 -m pytest tests/test_auth_persistence.py -q
```

