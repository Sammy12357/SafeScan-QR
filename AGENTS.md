# SafeScan QR Agent Instructions

## Agent skills

Project skills live under `.agents/skills/`. Use `safescan-ship` when preparing a website or backend release, `safescan-security-gate` for security-sensitive changes, `safescan-ui-states` for frontend work, `qr-decode-bench` for camera or decoder changes, and `go-ghost-recipe` for broker workflows. Read a skill when its scope matches the task; the user's current instructions and verified code state take precedence over older plans.

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
https://sqafe.com
```

For the Alpha Premium payment flow, verify:

```text
https://sqafe.com/pay/alpha
https://sqafe.com/pay/alpha/success
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

The old Stripe Payment Link must be disabled before card billing opens. The success page never grants access. New card subscriptions require an account-bound Checkout Session, recorded recurring consent, a verified Stripe webhook event, and the business and Stripe settings in `docs/legal/phase-1-payment-release.md`. The portal management path remains available to existing verified subscribers even if new checkout is closed.

## Test Commands

Use the bundled or local Python runtime available in the environment.

Focused payment persistence test:

```text
python -m pytest tests/test_auth_persistence.py -q
```

Broader auth persistence suite:

```text
python -m pytest tests/test_auth_persistence.py -q
```

