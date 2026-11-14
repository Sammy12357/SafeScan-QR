# Phase 6 API-key audit

Reviewed 2026-11-14 against the Phase 5 draft (`fd15470`).

## Current behavior

- `/admin/api-keys` creates a random key, stores only its SHA-256 hash, and
  allows an owner to mark a row revoked (`hackabull/routes_admin.py`). Its form
  stores the submitted scope list and expiry text without validating either.
- No request handler reads `api_keys.key_hash`, `scopes`, `expires_at`,
  `revoked_at`, or `last_used_at`. A repository-wide search found only the
  insert, listing, and revoke statements for this table.
- Bearer authentication in `hackabull/auth.py` looks up a token only in
  `sessions.id`. `/metrics` checks a separate `METRICS_TOKEN` in
  `hackabull/app_module.py`. The mobile bearer contract is therefore a
  session token, not an API key.

**Result:** generated API keys currently authorize no endpoint. There is no
expiry or scope decision to enforce at request time. Adding a verifier without
an agreed route-to-scope map could silently grant powers to previously issued
keys whose scopes and expiry values were never validated.

## Release gate for future API-key support

1. Decide which endpoints accept an API key and the exact scope needed for
   each. Keep owner/admin actions behind an explicit step-up design; do not
   infer a user's role from a key's creator email.
2. Validate a small allowlist of scopes and a UTC expiry with a maximum TTL at
   issuance. At every accepted request, reject unknown, revoked, inactive, or
   expired keys; require the endpoint's scope. Test the negative cases and
   ensure session and API-key authentication cannot be confused.
3. Revoke and replace any keys created under the current unvalidated form
   before enabling key authentication. Add safe usage auditing and a reviewed
   migration for `created_by`, which currently stores an email rather than a
   stable user ID.
4. Until these gates are met, label or hide the API-key creation UI before
   offering the feature to customers. Do not describe existing keys as usable
   credentials.

This audit makes no request-authentication or production configuration change.
