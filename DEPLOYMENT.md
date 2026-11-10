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

For a commercial deployment, set `GOOGLE_WEB_RISK_API_KEY` in Render. Web Risk receives the full URL being checked. Google Web Risk takes precedence over the legacy Safe Browsing key. The legacy `GOOGLE_SAFE_BROWSING_API_KEY` or `googe_api_key` is ignored by default; `SAFESCAN_ENABLE_NONCOMMERCIAL_SAFE_BROWSING=true` opts in only when that use is permitted by Google's terms or a separate agreement. Do not enable the legacy fallback solely to make scans appear complete.

PhishTank supplies the second required phishing signal without receiving individual customer URLs: SafeScan downloads the verified-online CSV feed into an indexed SQLite snapshot under `DATA_DIR` (normally `/var/data`) and matches exact canonical URLs locally. Register an app key through the [PhishTank developer page](https://phishtank.org/developer_info.php). Set `PHISHTANK_APP_KEY` and `SAFESCAN_PHISHTANK_TERMS_CONFIRMED=true` only after reviewing the [current Cisco terms linked by PhishTank](https://phishtank.org/terms.php) for this product; the [PhishTank FAQ](https://phishtank.org/faq.php) says commercial API use is allowed, but the current Cisco agreement should be checked before launch. The feed refreshes about hourly in the background. A successful snapshot remains usable for two hours; a missing, stale, invalid, or disabled snapshot makes the PhishTank check unverified. Exact matches to verified online phishing URLs are high risk. A fresh non-match means only that the URL is not in this feed, not that it is safe. The feed downloader limits compressed and expanded size and atomically replaces the previous snapshot only after validating the new one.

`GET /health/providers` reports configuration and local feed states without exposing credentials or claiming a live Google lookup succeeded. It returns `200` even when coverage is incomplete; `/health/ready` remains the storage and service readiness check. The required URL checks are Google Web Risk (or explicitly permitted legacy Safe Browsing), a fresh PhishTank feed, and redirect inspection. The scan response lists incomplete required checks in `unverifiedChecks`; `optionalChecks` remains empty for API compatibility. Branded QR generation requires all required checks to complete. Remove retired `VIRUSTOTAL_API_KEY` and `SAFESCAN_VIRUSTOTAL_*` values from Render's environment after deployment.

A scan that cannot complete a required reputation or redirect check must be shown as incomplete. Without a configured Google Web Risk key and a fresh, terms-approved PhishTank feed, web URL scans remain unverified and branded QR generation stays paused. `/api/qr/generate` refuses to stamp a branded QR unless the verdict is safe and verification status is complete. Monitor Web Risk errors and feed freshness: they reduce scan coverage and temporarily stop branded QR generation. A completed lookup means no *known* threat match was returned at scan time, not that a destination will remain safe.

Redirect inspection connects directly to the validated public IP for each hop and retains the original hostname for TLS verification. It intentionally ignores `HTTP_PROXY` and `HTTPS_PROXY`; ensure the deployment can make direct outbound HTTP/HTTPS connections or redirect checks will be reported as incomplete.

## Private QR payload retention

Non-URL QR payloads can contain authenticator seeds, Wi-Fi passwords, WalletConnect pairing keys, contact details, and payment information. The scanner displays the decoded value in the immediate `Cache-Control: no-store` result, but stores only a per-user keyed fingerprint and generic verdict metadata for scan counting and history. Uploaded QR files are analyzed in memory and are not retained by normal scan routes. Non-URL payloads are not submitted to external URL reputation or redirect services; embedded URL-shaped text receives local checks and an unverified/caution result instead.

Set `QR_PAYLOAD_FINGERPRINT_KEY` to a stable, random secret of at least 32 bytes in Render. If absent, an `AIRDROP_ADMIN_SECRET` of at least 32 bytes is used; if neither strong key is configured, an in-memory random key protects private payloads but duplicate-scan recognition can reset when the service restarts. Never store a decoded QR secret in this environment variable.

### Earlier stored scans

This change does not erase records or uploads created by older versions. Before any cleanup, take a protected backup of `/var/data/qr_cache.db` and the `DATA_DIR/uploads` directory (or the configured S3/R2 bucket), then verify that the backup can be restored. Plan a maintenance window and review these locations without printing payload values in logs:

- `scan_history.url` and `scan_history.signals`
- `scans.url_found`, `scan_events.url_found`, and `scan_events.payload_hash`
- `scan_velocity.last_scan_url`, `fraud_flags.metadata` entries with a `url` field, and any non-web `url_blocklist.url` entries
- `ml_cache.sqlite` → `ml_cache.url_key` for non-URL predictions
- `upload_artifacts.object_key` and the corresponding `DATA_DIR/uploads/<object_key>` files or S3/R2 objects

Treat all earlier uploaded QR files as potentially sensitive because the stored image type does not reveal whether it encodes a secret. The dry-run-first database helper reports counts without printing payloads:

```text
python scripts/scrub_legacy_private_qr.py --database /var/data/qr_cache.db --ml-cache /var/data/ml_cache.sqlite
```

After stopping the service for a maintenance window, verifying a protected off-host backup plan, and setting a strong `QR_PAYLOAD_FINGERPRINT_KEY`, apply the database cleanup with an unused backup path in an existing protected directory:

```text
python scripts/scrub_legacy_private_qr.py --database /var/data/qr_cache.db --ml-cache /var/data/ml_cache.sqlite --execute --backup /protected-backups/safescan-before-private-qr-cleanup.db --confirm "SCRUB PRIVATE QR DATA"
```

The helper creates and verifies SQLite backups before changing records. It replaces old non-URL scan values with keyed references, retains scan counts, and vacuums/checkpoints SQLite. Because the old ML cache strips URL schemes from its keys, the helper purges the **entire disposable ML prediction cache**, including web predictions; future scans recompute them. It deliberately does **not** delete upload objects or `upload_artifacts` rows. Use its `upload_artifacts_manual_cleanup` count to inventory local `DATA_DIR/uploads/<object_key>` files and S3/R2 objects, then back up and remove those under an approved retention plan. Account for backup and object-store version retention too. The normal history and scan APIs redact legacy non-URL records on read, but the underlying historical copies remain until this cleanup is completed. `QR_UPLOAD_RETENTION_DAYS` is not currently an automatic deletion job.

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
