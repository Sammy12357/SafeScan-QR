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
