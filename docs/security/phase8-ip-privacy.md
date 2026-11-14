# Phase 8 IP registry privacy release gate

This change stores a salted SHA-256 digest in new `ip_registry.ip_address` rows
and records a compact `(ip_hash, user_id)` account aggregate. Fraud checks read
both that digest and a matching raw legacy IP during the transition. Expired
detail rows are folded into the aggregate before deletion, so the lifetime
distinct-account threshold still works. New IP fraud flags contain `ipHash`,
never the literal IP. Maintenance also scrubs the old `ip` metadata key in
existing IP clustering flags. The daily maintenance command clears
`audit_logs.ip_address` after 30 days without deleting the audit event.

## Before release

1. **Verify the production secret in Render.** `PRIVACY_HASH_SALT` must be a
   stable, randomly generated secret of at least 32 characters. Generate one
   with `python -c 'import secrets; print(secrets.token_urlsafe(32))'` and enter
   it in the Render web service environment. Do not commit, print from Render,
   or send the value to anyone. The startup check rejects an absent or obvious
   placeholder salt in production; the check cannot prove randomness. A weak
   secret permits offline guessing of IPv4 hashes. Do not release until an
   operator confirms its entropy and persistence across restarts.
2. Take a consistent, access-restricted backup of the live SQLite database.
   Rehearse this migration and restore on a copy of that backup. The old raw
   rows are deleted during maintenance, so rollback to the pre-migration code
   needs the backup.
3. Check whether the salt was already in use. Keep the same strong salt if so.
   Rotating it changes all IP digests and breaks historical correlation with
   pre-existing hashed rows; plan a separate rotation if the old value is weak.
4. Deploy only after the startup secret check passes. Verify that a new scan
   or signup writes a 64-character digest to `ip_registry`, and that the
   clustering flag metadata contains `ipHash` with no literal `ip` field.

## Retention operation

Each new IP event processes up to 100 expired registry rows. Schedule the
following command **daily** against the same persistent Render database to
drain quiet-period backlogs. It runs at most 100 batches of 1,000 registry
rows, 1,000 legacy flags, and 1,000 expired audit IP fields each, then prints
counts only. Repeat it if it reports `backlog_possible=true`. Set up the job
after rehearsing it on the backup; no job is created by this code change.

```sh
python scripts/security/ip_registry_maintenance.py --apply --max-batches 100
```

The cutoff is 30 days. Detailed `ip_registry` rows older than the cutoff are
deleted only after their account association is included in the aggregate.
Legacy raw rows younger than 30 days remain available to the fraud counter
until they expire. The aggregate has no automatic expiry because the existing
fraud rule uses a lifetime account count. A later policy decision is needed
for aggregate expiry and salt rotation.

## Scope and remaining work

This migration covers `ip_registry`, IP clustering flag metadata, and
`audit_logs.ip_address`. The integrated Phase 8 branch also stops writing the
unused `users.login_ip` field and clears existing values at schema startup.
Old SQLite pages, WAL files, and backups may still contain earlier raw values;
rehearse a consistent backup and restore into a fresh database and apply the
approved backup retention policy before claiming physical erasure. Other
metadata outside the IP clustering flags may still need review. The Phase 8 audit metadata redaction and
broader privacy export work must be reviewed before claiming that all stored
IP data is hashed or removed after 30 days. The daily job and production
secret have not been configured by this branch.
