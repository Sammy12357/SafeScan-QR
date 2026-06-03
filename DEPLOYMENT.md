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

If an older deployment already has a database at `/app/data/qr_cache.db`, copy it to `/var/data/qr_cache.db` before changing the environment variables.

The app also checks both `/app/data/qr_cache.db` and `/var/data/qr_cache.db` at startup and prefers the file with existing user/scan data. This protects deployments that previously mounted a Render disk at `/app/data`.

The readiness endpoint includes a database persistence check:

```text
GET /health/ready
```

`database.persistent` must be `true` in production. If it is `false`, the service is using reset-prone storage and leaderboard data can be lost on deploys or restarts. For a custom persistent mount, set `PERSISTENT_DATA_DIR` to that mount path, or set `LEADERBOARD_STORAGE_PERSISTENT=true` only after confirming the database path is durable.
