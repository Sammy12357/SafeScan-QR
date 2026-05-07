# SafeScan QR Security

## Current Stack

SafeScan QR currently runs as a FastAPI/Python application with SQLite storage in `qr_cache.db`. The original security plan referenced Node/Express and TypeScript files; those items must be interpreted through the current FastAPI app until the backend is migrated.

## Implemented Controls

- Server-side user roles and status fields on `users`: `user`, `admin`, `owner`; `active`, `suspended`, `deleted`.
- Built-in admin allowlist includes `homzajoe@gmail.com` and `restreposamuel2004@gmail.com`; set `ADMIN_EMAILS` in Render to keep this explicit.
- Server-side sessions in the `sessions` table, issued as HTTP-only, Secure, SameSite=Strict cookies.
- Suspended or deleted users are rejected when loading sessions.
- Admin pages now require an active session with `admin` or `owner` role.
- `/admin/*` dashboard pages now include users, scans, reports, airdrop, fraud flags, audit logs, owner API keys, and owner settings.
- API keys are generated server-side, shown once, and stored only as SHA-256 hashes with a short hint.
- Scan submission no longer trusts the hidden `user_email` form field; the server derives the email from the session.
- URL analysis validates URL shape, max length, scheme, hostname, and blocks localhost/private/internal Render targets before reputation checks or redirects.
- Redirect tracing follows redirects manually and validates every hop before requesting it.
- Wallet connection now uses a server-issued 5-minute nonce and Ed25519 message-signature verification before a wallet is stored.
- Wallet nonces are single-use, rotated after failed verification, rate-limited per wallet address, and cleaned up by a background task.
- Verified wallets are stored in the `wallets` table; scan submission no longer trusts client-submitted wallet addresses.
- Verified wallets are checked asynchronously against Solana RPC for balance, transaction count, and approximate wallet age.
- Scan count increments are server-side only, deduplicated by user and payload, and same-payload repeats inside 60 seconds do not increment.
- Device fingerprint hashes are collected on the frontend and sent to the backend for exact-match anti-fraud clustering.
- Fraud checks now run after signup, scan, and wallet submission events. Signals are stored in `fraud_flags` and roll up into `users.fraud_score` / `users.airdrop_status`.
- Audit logs are stored for login, logout, permission denial, QR scans, airdrop sweeps, account deletion, and rate limit hits.
- Basic in-memory rate limiting is active for public pages, `/api/*`, and `/api/analyze`.
- Security headers are added on every response, including HSTS, CSP, Referrer-Policy, Permissions-Policy, and X-Content-Type-Options.
- Data export and erasure actions require the active session email to match the requested email before completing automatically.

## Protected Routes

- Public: `GET /`, legal/product/resource pages, `POST /waitlist`, `POST /api/consent`.
- Optional auth: `POST /api/analyze`.
- Active session required: `GET /api/wallet`, `POST /api/wallet/nonce`, `POST /api/wallet/verify`, `DELETE /api/wallet`, `POST /search_qr_api`, `GET /account/settings`, `POST /auth/logout`.
- Admin session required: `GET /legal/consent-log`, `GET /admin/data-processing-log`, `GET /admin/report-breach`, `POST /admin/report-breach`.
- Admin session required: `GET /admin`, `/admin/activity`, `/admin/users`, `/admin/scans`, `/admin/reports`, `/admin/risk-logs`, `/admin/airdrop`, `/admin/airdrop/fraud`, `/admin/airdrop/wallets`, `/admin/logs`.
- Owner session required: `GET/POST /admin/api-keys`, `POST /admin/api-keys/{id}/revoke`, `GET /admin/settings`, `GET /admin/export/users`, owner role changes and deletes.
- Admin session or valid `AIRDROP_ADMIN_SECRET`: `GET /trigger-airdrop-secret`.

## Audit-Logged Actions

- `user.login`
- `user.logout`
- `auth.failed`
- `auth.permission_denied`
- `auth.rate_limited`
- `qr.scanned`
- `wallet.nonce_issued`
- `wallet.verification_failed`
- `wallet.connected`
- `wallet.disconnected`
- `wallet.onchain_verified`
- `account.deleted`
- `admin.view_logs`
- `admin.breach_report_created`
- `airdrop.sweep_executed`
- `airdrop.sweep_failed`

## Rate Limits

- Public pages: 300 requests per 15 minutes per IP.
- General API: 100 requests per 15 minutes per IP.
- Analyze API: 30 requests per hour per authenticated user, falling back to IP for guests.
- Wallet nonce API: 5 nonce requests per hour per wallet address. Exceeding this creates a medium fraud flag.

## Remaining Gaps Before Production

- Move from SQLite to Postgres/Supabase with real migrations and database-level enum/check constraints for all security fields.
- Add a complete permission constants module if the app is split into packages; current checks live in `hackabull.py`.
- Add CSRF tokens for every state-changing form.
- Replace shared-secret fallback on `/trigger-airdrop-secret` with owner-only session access once operational automation is updated.
- Complete referral counting UX and referral tree visualization once real referral events exist. The database table exists, but public referral flows are still minimal.
- Add a persistent distributed rate limiter, such as Redis, before scaling beyond one Render instance.
- Add a full automated security test suite.
- Rotate any secrets that were ever committed before this hardening pass.

## Secret Rotation

Update these environment variables in Render, redeploy, and invalidate sessions by clearing the `sessions` table if auth secrets or session behavior changes:

- `GOOGLE_CLIENT_SECRET`
- `SESSION_SECRET`
- `JWT_SECRET`
- `AIRDROP_ADMIN_SECRET`
- `PRIVACY_HASH_SALT`
- `VIRUSTOTAL_API_KEY`
- `GOOGLE_SAFE_BROWSING_API_KEY`
- `ANTHROPIC_API_KEY`
- `OPENAI_API_KEY`
- `SOLANA_RPC_URL`

## Security Report Process

Send vulnerability reports to `privacy@safescan-qr.onrender.com` or the address configured in `ADMIN_EMAIL`. Include the affected route, reproduction steps, expected impact, and whether any user data may have been exposed.

## Deployment Checklist

- No new route is added without an explicit auth decision.
- No request body can set `role`, `status`, `scan_count`, or ownership fields.
- No URL-fetching code runs without `validate_public_url`.
- No raw DB record is returned from JSON APIs if it contains internal or private fields.
- `.env`, `.env.local`, SQLite databases, logs, and temporary dependency folders are not committed.
- Security tests pass once the test suite is added.
