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

## URL reputation and branded QR generation

For a commercial deployment, set `GOOGLE_WEB_RISK_API_KEY` in Render. Google Web Risk takes precedence over the legacy Safe Browsing key. The legacy `GOOGLE_SAFE_BROWSING_API_KEY` or `googe_api_key` is ignored by default; `SAFESCAN_ENABLE_NONCOMMERCIAL_SAFE_BROWSING=true` opts in only when that use is permitted by Google's terms or a separate agreement. Do not enable the legacy fallback solely to make scans appear complete.

VirusTotal also requires a key licensed for commercial use. Set `VIRUSTOTAL_API_KEY` and `SAFESCAN_VIRUSTOTAL_LICENSED=true` only after confirming the license. A key without that flag is ignored. A licensed lookup still sends the full scanned URL to VirusTotal, encoded in the `GET /api/v3/urls/{url_id}` path; base64 encoding does not make URL tokens private. On a cache miss, SafeScan does not additionally submit the URL for analysis by default. VirusTotal shares submitted URL data with its partners. `SAFESCAN_VIRUSTOTAL_SUBMIT_UNKNOWN_URLS=true` enables that submission only after reviewing the data-sharing behavior. An unknown or pending URL remains unverified either way.

`GET /health/providers` reports provider configuration states without exposing credentials or claiming that a live lookup succeeded. It returns `200` even when coverage is incomplete; `/health/ready` remains the storage and service readiness check. Missing or failing provider checks produce an incomplete verdict, and branded QR generation is paused until all required checks complete.

A scan that cannot complete a required reputation or redirect check must be shown as incomplete. `/api/qr/generate` refuses to stamp a branded QR unless the verdict is safe and verification status is complete. Monitor provider errors and quota exhaustion: they reduce scan coverage and temporarily stop branded QR generation. A completed lookup means no *known* threat match was returned at scan time, not that a destination will remain safe.

Redirect inspection connects directly to the validated public IP for each hop and retains the original hostname for TLS verification. It intentionally ignores `HTTP_PROXY` and `HTTPS_PROXY`; ensure the deployment can make direct outbound HTTP/HTTPS connections or redirect checks will be reported as incomplete.

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
