# Identity migration inventory

## Phase 5 email and ownership collision audit

Run `email_ownership_dry_run.py` against a **consistent standalone offline
SQLite backup** before changing email matching, uniqueness, child ownership,
or paid/wallet entitlements. It refuses Render/production runtimes, configured
live database paths, symlinks, and backups with SQLite journal/WAL sidecars.
The SQLite connection is `mode=ro&immutable=1` with `query_only=ON`; the source
SHA-256 is checked before and after the inventory. The script does not write
to the database or propose account merges.

```sh
python scripts/security/email_ownership_dry_run.py \
  --database /secure/path/standalone-backup.db \
  --private-report /secure/path/email-ownership-review.json
```

Stdout contains **aggregate counts only**. The optional JSON report is
created exclusively with mode `0600`; an existing file is never overwritten.
It contains email addresses, account IDs, exact `(issuer, full subject)`
identity keys for collision review, and offline row IDs. Keep it outside the
repository, share it only with the reviewers, and delete it after the release
decision. QR URLs, payload hashes, password hashes, wallet addresses, IPs,
tokens, and payment metadata are never copied into the report. The report's
`database_sha256` binds its row IDs to the audited backup.

The review key applies NFKC and casefold to the local part, then IDNA UTS #46
to the domain. It does **not** remove plus tags or dots. This is a conservative
collision search, not proof that two addresses belong to one mailbox: SMTP
local parts can be case sensitive, and provider alias rules vary. A matching
email never links two federated identities. The exact issuer and **full**
subject remain the identity key; an Auth0 `google-oauth2|123` subject is not
equivalent to Google subject `123`.

The summary separates invalid or duplicate account IDs, collision groups,
privileged/paid/wallet groups, ambiguous scan **rows**, ambiguous email
**references**, orphaned email and user ID references, missing user IDs, and
email/user ID mismatches. One row with two email columns can contribute two
reference counts. Mixed-format owner fields in `wallets`, `wallet_nonces`,
fraud, velocity, device, admin, and audit tables are resolved by exact
`users.google_id` first. Only a value that is not a known account ID is
examined as a possible legacy email; unknown IDs, ambiguous legacy emails,
and malformed values are reported separately. A stable ID that happens to
look like an email still remains an ID. Even a legacy email with just one
current user is listed for review and is never linked automatically. Public
submissions, such as waitlist signups, may have no SafeScan user; they count
toward ambiguous references but not orphaned owned rows. `coverage` in the
private report lists absent tables or columns, which may be expected for older
backups. Review that coverage before interpreting zero counts.

### Phase 5 release gates

1. Obtain a consistent offline backup and retain its hash. Run both identity
   inventories against the **same** backup. Keep their private reports out of
   the repository. Do not run either audit against the live Render database.
2. Manually resolve or quarantine every canonical collision, especially
   groups involving owner/admin roles, active subscriptions, or wallet
   evidence. Review every ambiguous `scan_history`, `scans`, and `scan_events`
   row, legacy email owner reference, orphan, missing owner ID,
   invalid/duplicate account ID, and email/user ID mismatch. Zero counts are
   required for unattended migration; an exception needs a documented owner
   disposition and fail-closed handling. Audit findings alone authorize no
   merge or transfer.
3. Migrate email-keyed ownership paths to immutable user IDs or make each
   affected path fail closed before changing uniqueness or normalization.
   This includes scans, wallets, rewards, fraud, referrals, paid access,
   admin reports, and privacy/deletion flows. Remove the startup backfills in
   `hackabull/schema.py` that select a user with `lower(email)` and `LIMIT 1`
   until ownership has been reviewed and mapped.
4. Preserve every `(issuer, full subject)` mapping exactly. Require verified
   dual-account proof for any later explicit account link; neither casefold,
   IDNA, nor a verified email alone is ownership proof. Rehearse migrations
   and rollback on a new offline copy, then decide session treatment and
   production cutover separately with the owner.


This tool is a **dry run only**. It opens a SQLite backup read only and proposes
provider-scoped `(provider, issuer, subject)` identities for manual review. It
does not change accounts, sign-in, sessions, or the database. Do not run it
against the live database.

```sh
python scripts/security/identity_dry_run.py \
  --database /path/to/offline-backup.db \
  --auth0-issuer https://your-tenant.auth0.com/ \
  --private-report /secure/path/identity-review.json
```

Only counts appear on stdout. The optional detailed report contains account
identifiers and email addresses. The tool creates that file with permission
`0600` and refuses to overwrite it. Store it outside the repository, restrict
access, and delete it after review. Password hashes, session tokens, IP
addresses, and audit metadata are never included in the report.

The candidates are proposals, **not** a migration or proof that two accounts
belong together. A matching email, even one verified by Google, never links
accounts. A full legacy Auth0 subject such as `google-oauth2|123` remains in
the Auth0 issuer namespace; `123` is never treated as equivalent to it. The
current mobile login code discarded that prefix before storing the account, so
many Auth0 identities cannot be recovered from the database. Such accounts
need explicit dual-account sign-in or another verified ownership process.

Review all conflicts and owner/admin accounts before any write migration.
Keep existing `users.google_id` primary keys because sessions and other tables
reference them. A later migration should add a separate identity table and
must include a rollback plan and a deliberate session policy. Existing web
Google login events do not record a provider, so those rows are marked
`provider_unconfirmed` unless other reliable evidence exists. The supplied
Auth0 issuer must be checked against actual verified tokens; the database
does not prove it.

## Phase 2 release gate

The candidate application code now adds `user_identities` and accepts a
federated sign-in only when its exact `(issuer, subject)` is mapped to an
existing account, or when there is no account with that email. It deliberately
refuses to guess a mapping from an email address. Deploying that code before
reviewing and applying legacy mappings would make some returning users unable
to sign in again, although existing sessions would continue until expiry.

Before release, obtain a consistent offline SQLite backup, run this inventory,
review every owner/admin and local-credential conflict privately, and prepare
an explicit mapping backed by provider subject proof. Never infer a missing
Auth0 connection prefix from the old `google_id`. Decide with the owner whether
to revoke existing sessions and when. No migration or session revocation has
been run as part of this branch.

For Auth0, inspect the enabled application connections and configure the
post-login Action in `docs/security/auth0-post-login-action.js` for the actual
SafeScan client IDs. The server checks `email_verified` independently.

This mapping follows [Google's requirement to identify users by `sub`](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token),
[Auth0's requirement to authenticate both accounts before linking](https://auth0.com/docs/manage-users/user-accounts/user-account-linking/link-user-accounts),
and [Auth0's post-login verification guidance](https://support.auth0.com/center/s/article/implement-email-verification-to-prevent-access-with-unverified-emails-in-auth0).

## Apply a reviewed mapping to an offline copy

`identity_apply.py` is a rehearsal and preparation tool. It reads a standalone
SQLite backup **without changing it**, checks an explicitly approved mapping
file against that backup, and writes a **new** private database copy only when
`--apply` is present. It refuses to run in the Render/production runtime or
against the configured application database or data directory, symlinked
paths, and backups with WAL sidecars. The output must not exist. A failed
migration removes the output.

First finish the dry run and obtain proof of the exact issuer and full subject
for each account, especially owners and admins. Do not infer an Auth0 subject
from a matching email or a stripped suffix. An approved mapping file contains
no passwords or tokens, but it does contain account IDs and emails, so keep it
outside the repository with mode `0600`. Bind it to the specific backup file
using the output of `shasum -a 256 /secure/path/offline-backup.db`:

```json
{
  "format": "safescan-identity-mappings-v1",
  "database_sha256": "the-64-character-lowercase-sha256-of-the-backup",
  "mappings": [
    {
      "provider": "google",
      "issuer": "https://accounts.google.com",
      "subject": "exact-google-sub-from-verified-token",
      "user_id": "existing-users.google_id",
      "email_at_link": "person@example.com",
      "email_verified": true
    }
  ]
}
```

The `email_verified` value records the reviewer's proof; the tool cannot
verify a historical provider claim on its own. It checks that every mapped
account is active, its email still matches the approved file, a stored Google
subject does not conflict, and an existing identity mapping is identical.
Write `email_at_link` in the same lowercase form used by the sign-in path;
the tool rejects an uppercase or stale value.
For Auth0 entries, include the **full** subject such as `google-oauth2|123`
and pass the verified tenant issuer with `--auth0-issuer`. Mapping an active
admin or owner additionally requires `--allow-privileged`.

```sh
chmod 600 /secure/path/approved-mappings.json
python scripts/security/identity_apply.py \
  --database /secure/path/offline-backup.db \
  --approved-mappings /secure/path/approved-mappings.json \
  --auth0-issuer https://your-tenant.auth0.com/ \
  --allow-privileged \
  --output /secure/path/migrated-copy.db

# After the owner reviews the reported counts, create the copy:
python scripts/security/identity_apply.py \
  --database /secure/path/offline-backup.db \
  --approved-mappings /secure/path/approved-mappings.json \
  --auth0-issuer https://your-tenant.auth0.com/ \
  --allow-privileged \
  --output /secure/path/migrated-copy.db \
  --apply
```

Only aggregate mapping counts are printed. The copied database is created
with permission `0600`; all inserts occur in one SQLite transaction. Running
again on that copy with an updated source hash and the same mappings inserts
nothing. **Do not replace the live database with an old copy** while the app
is accepting writes. The live migration, session policy, backup/restore drill,
and Auth0 Action remain separate release steps requiring owner review.

Once the identity mapping has been reviewed and installed, an owner can be
bootstrapped from an existing **verified Google identity**. The command checks
the exact Google subject and expected email against `user_identities` and
`users`, then writes an audit entry. It never grants a role by email alone.
Run it only after reviewing the target account and database backup:

```sh
python -m hackabull.cli grant-owner \
  --google-sub 'the-exact-google-sub' \
  --expected-email 'owner@example.com' \
  --apply
```

Omitting `--apply` makes no change. `--database /path/to/backup.db` can be
used to rehearse against an offline copy. This command has not been run on
production as part of this branch.
