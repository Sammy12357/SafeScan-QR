# Identity migration inventory

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
