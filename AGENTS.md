# SafeScan QR Agent Instructions

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

7. Verify the live site at:

```text
https://safescan-qr.onrender.com
```

For the Alpha Premium payment flow, verify:

```text
https://safescan-qr.onrender.com/pay/alpha
https://safescan-qr.onrender.com/pay/alpha/success
```

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

The Alpha Premium Stripe link is:

```text
https://buy.stripe.com/00w3cxfdAb7OcKB4sC87K01
```

The Stripe Payment Link success redirect should point to:

```text
https://safescan-qr.onrender.com/pay/alpha/success
```

The app records signed-in Alpha Premium success-page visits in the long-term database table `alpha_subscriptions`. A Stripe webhook is still the preferred follow-up for fully verified automatic activation.

## Test Commands

Use the bundled or local Python runtime available in the environment.

Focused payment persistence test:

```text
python -m pytest tests/test_auth_persistence.py::test_alpha_payment_uses_stripe_link_and_records_purchase_date -q
```

Broader auth persistence suite:

```text
python -m pytest tests/test_auth_persistence.py -q
```

