# SafeScan QR Deployment Notes

## Persistent leaderboard and scan data

SafeScan stores users, sessions, scan counts, scan history, leaderboard rows, referrals, wallets, and admin records in SQLite by default.

For production on Render, mount a persistent disk at:

```text
/var/data
```

Use these environment variables:

```text
DATA_DIR=/var/data
SQLITE_DB_PATH=/var/data/qr_cache.db
DATABASE_URL=sqlite:////var/data/qr_cache.db
```

Do not store production data in `/app/data` unless a Render persistent disk is explicitly mounted there. The `/app` directory is rebuilt during deploys, so SQLite data there can disappear after a push or service restart.

The app refuses to use a relative fallback database such as `qr_cache.db` in production unless `SAFESCAN_ALLOW_EPHEMERAL_DB=true` is explicitly set. That guard keeps leaderboard and scan history data from silently landing on Render's ephemeral filesystem.

If an older deployment already has a database at `/app/data/qr_cache.db`, copy it to `/var/data/qr_cache.db` before changing the environment variables.

The app also checks both `/app/data/qr_cache.db` and `/var/data/qr_cache.db` at startup and prefers the file with existing user/scan data. This protects deployments that previously mounted a Render disk at `/app/data`.

The readiness endpoint includes a database persistence check:

```text
GET /health/ready
```

`database.persistent` must be `true` in production. If it is `false`, the service is using reset-prone storage and leaderboard data can be lost on deploys or restarts. For a custom persistent mount, set `PERSISTENT_DATA_DIR` to that mount path, or set `LEADERBOARD_STORAGE_PERSISTENT=true` only after confirming the database path is durable.

## Auth0 mobile sign-in

The mobile app uses Auth0 Universal Login and sends the resulting Auth0 ID token to:

```text
POST /auth/verify
```

Set these variables on the Render service:

```text
AUTH0_DOMAIN=your-tenant.us.auth0.com
AUTH0_CLIENT_IDS=your-native-app-client-id
```

Use the Auth0 tenant hostname only for `AUTH0_DOMAIN`; do not include `https://` or a trailing slash. `AUTH0_CLIENT_IDS` accepts a comma-separated list when more than one Native application build is supported. These identifiers are configuration rather than secrets, but production values belong in Render so every deployment is explicit.

The backend accepts an Auth0 token only when its issuer matches `AUTH0_DOMAIN` and at least one value in its `aud` claim matches `AUTH0_CLIENT_IDS`. A tenant or client-ID mismatch causes `/auth/verify` to return `401`. The endpoint otherwise treats a token from an unrecognized issuer as a Google token, whose verification also fails with `401`.

In the Auth0 Dashboard, confirm that the mobile client is registered as a **Native** application using Authorization Code Flow with PKCE. Configure its Allowed Callback URLs and Allowed Logout URLs for every supported iOS and Android application identifier. Those URLs are consumed by the mobile app, not the Render backend, and must exactly match the mobile Auth0 SDK configuration.

Before deploying:

1. Confirm the mobile app uses the same Auth0 domain and Native application client ID.
2. Confirm the Native application's Google/social connection is enabled if the app offers that sign-in method through Universal Login.
3. Set `AUTH0_DOMAIN` and `AUTH0_CLIENT_IDS` in Render and redeploy.
4. Complete a real mobile login and verify `POST /auth/verify` returns `200`.
5. Test a token from an unapproved client ID and confirm the endpoint returns `401`.

The backend currently contains development fallback values in `hackabull/config.py` so local development can start without Auth0 variables. Production must not rely on those defaults.
