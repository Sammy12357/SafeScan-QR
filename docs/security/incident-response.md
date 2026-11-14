# SafeScan incident response

This is an operator runbook, not an automated user notification. Use
[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) as the
overall preparation, analysis, containment, and recovery framework. Record
who is incident lead, when the issue was discovered, affected systems and
accounts, evidence preserved, decisions, and the next update time.

## Detect and triage

Phase 10 alerts are **off by default**. With `SECURITY_ALERTS_ENABLED=true`,
set either `SECURITY_ALERT_DISCORD_WEBHOOK_URL` (a Discord `https://discord.com/api/webhooks/...`
URL) or `SECURITY_ALERT_EMAIL_TO` with configured SMTP. An invalid or missing
destination configuration prevents startup; startup does not prove connectivity.
Test each destination on staging before enabling
it on Render. The application sends only a fixed event name, count, and window;
it never sends account IDs, email addresses, IPs, QR payloads, links, tokens,
Stripe headers, or audit metadata. Delivery uses a bounded in-memory queue,
five-second read timeout for Discord, and a ten-minute cooldown. Failed delivery
gets two bounded retries off the request path, then permits a new alert after
30 seconds of new events. A process restart or persistent sink outage can still
lose an alert. If both sinks are configured, a retry may duplicate a message at
the sink that succeeded. Counters and
cooldowns reset on restart and are per worker, so keep one Render worker or
move this logic to shared durable monitoring before scaling. A full queue
logs a generic warning and drops the alert, then permits a retry after 30
seconds; it must not block customer flows.

Current rules: 20 `auth.failed` events in ten minutes; any admin permission
denial, role change, API-key creation, or airdrop run; five Stripe signature
failures in ten minutes; ten HTTP 5xx responses in five minutes. The latter
includes readiness failures. Review `/admin/audit-logs`, Render logs, Stripe
delivery logs, and the provider dashboards before treating a count as a
confirmed breach. An alert is a prompt to investigate, not proof of compromise.

## Contain and preserve evidence

1. Record the time window and affected Render deploy revision. Limit access to
   the incident channel; do not paste credentials, payloads, database rows,
   webhook URLs, or customer details into chat or issue trackers. Until the
   Phase 9 structured-log work is released, treat existing Render logs as
   sensitive because exception paths and errors may contain user data.
2. Save relevant Render and provider logs with access controls. Take a
   consistent SQLite online backup and encrypt it offsite using the
   [Phase 8 backup runbook](phase8-storage-backup.md). Preserve originals
   before changing accounts or keys.
3. For a suspected airdrop/key incident, set `AIRDROP_ENABLED=false` and
   `SOLANA_MAINNET_ENABLED=false` in Render and redeploy before investigating
   on-chain activity. For abuse of a public form, use a reversible Cloudflare
   rule or the form's feature flag while preserving the request evidence.
4. Decide whether to revoke one account's sessions or all sessions. The
   existing Profile action revokes all devices for one authenticated account.
   The all-account operation below also revokes remembered-device tokens.

### Emergency all-account session revocation

Take a backup first. Run this once from a trusted Render shell against the
**actual** `/var/data/qr_cache.db` used by the service, during a controlled
incident window. It is one SQLite write transaction with two updates because
`sessions` and `persistent_sessions` are separate tables:

```python
import sqlite3
from datetime import datetime, timezone

stamp = datetime.now(timezone.utc).isoformat()
with sqlite3.connect('/var/data/qr_cache.db') as conn:
    conn.execute('BEGIN IMMEDIATE')
    conn.execute('UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE revoked_at IS NULL', (stamp,))
    conn.execute('UPDATE persistent_sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE revoked_at IS NULL', (stamp,))
```

Confirm a browser session, mobile bearer session, and remembered device now
fail. Operators will be signed out too. This does **not** revoke IdP tokens;
if an attacker can still obtain a valid Auth0 or Google token, they may sign
in again. Contain that source in the IdP dashboard as well.

An owner-only admin button would make this easier, but it must require fresh
federated reauthentication, CSRF protection, a clear confirmation step, and
an out-of-band recovery route. `sessions.created_at` is not proof of recent
federated login because a remember token can create a new session. That
step-up control is an open Phase 6 release gate, so this draft does not add a
global revoke button.

## Rotate exposed credentials

Rotate in the provider dashboard, update Render Environment, redeploy, verify
the new credential, and disable the old one. Never place secrets in git,
screenshots, issue bodies, or audit metadata. Decide the rotation order from
the actual exposure; an app restart alone does not revoke a provider key.

| System | SafeScan setting and response |
| --- | --- |
| Google sign-in | `GOOGLE_CLIENT_ID` is a public client identifier; this server has no Google OAuth client secret. If the OAuth client or owning Google account is compromised, secure that Google account, create or reset the affected client in Google Cloud, update the ID and allowed origins, and test login. Rotate `GOOGLE_WEB_RISK_API_KEY` separately in Google Cloud credentials and restrict it to the required API. [Google credential guidance](https://developers.google.com/workspace/guides/manage-credentials). |
| Auth0 | `AUTH0_DOMAIN` and `AUTH0_CLIENT_IDS` identify the tenant/apps; this server does not store an Auth0 client secret. Review enabled connections and sessions in the tenant, rotate any exposed app client secret there, and coordinate [tenant signing-key rotation](https://support.auth0.com/center/s/article/Tenant-Signing-Key-Rotation) only if signing keys are affected. Update SafeScan's accepted issuer/audience as needed and test mobile and web login. |
| Stripe | Roll the endpoint's webhook signing secret in Stripe Workbench, set `STRIPE_WEBHOOK_SECRET` on Render, and test a signed event. The app accepts one secret at a time, so coordinate cutover and inspect failed/retried deliveries. A Payment Link ID is not a secret. |
| SMTP | Rotate `SMTP_PASSWORD` or the provider API credential, update Render, and test delivery to an operator address. Review provider send logs for misuse. |
| S3 or R2 | Create a new bucket-scoped `S3_ACCESS_KEY_ID`/`S3_SECRET_ACCESS_KEY` pair, update Render, verify a private upload/read, then revoke the old pair. Review bucket access logs and any public bucket settings. Keep object permissions narrow; see [storage policy](phase8-storage-backup.md). |
| Solana | Set airdrop flags off first. `SOLANA_PRIVATE_KEY` controls the funding wallet and cannot be made safe by changing its env value alone. If exposed, generate a new keypair under trusted custody, assess and move remaining assets only with owner authorization, update the configured signer, and monitor the old address. `ALPHA_SOLANA_RECIPIENT` is a public address. |
| Airdrop trigger | Replace `AIRDROP_ADMIN_SECRET` with a fresh high-entropy value in Render and redeploy; test that the old value fails. Keep the airdrop disabled during investigation. |
| App sessions and privacy | Rotate `SESSION_SECRET`/`CSRF_SECRET` if exposed, plus `METRICS_TOKEN`, `DISCORD_CLIENT_SECRET`, `DISCORD_BOT_TOKEN`, `TURNSTILE_SECRET_KEY`, and the alert webhook URL as applicable. Changing `PRIVACY_HASH_SALT` affects historical IP hashes and fraud joins; plan its data migration before cutover. Revoke database sessions separately. |

## Notify and recover

Use `/admin/report-breach` to record the internal breach assessment. That page
does not send regulatory or user notices. Identify the affected people and
data categories from verified evidence, then have the incident lead and legal
adviser determine notification duties for the applicable jurisdictions. A
user notice should state what happened, what information was affected, what
SafeScan did, what the user should do, and how to reach a monitored support
contact. Avoid sending unnecessary QR payloads, wallet secrets, or raw logs.

Restore from a verified backup only into a staging environment first. Confirm
login, session revocation, scan history, private uploads, reputation coverage,
payment webhook handling, airdrop disabled state, and alert delivery. Record
the recovery time and remaining risk before returning traffic. Follow up with
root-cause fixes and a review of alert thresholds and retention.
