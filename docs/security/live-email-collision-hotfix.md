# Live-main email collision confidentiality hotfix

Base: `origin/main` at `de842103f222aaa9c000a31c758d3e45695b5da0`. This is a standalone hotfix; it does not depend on the Phase 2–8 draft stack.

## What changes

Account ownership is checked with a conservative canonical email key: NFKC/casefold local part plus UTS #46 IDNA domain. It includes inactive/deleted account rows and does not guess plus-tag or dot aliases. `idna` is now a direct pinned dependency. Checking uniqueness currently scans `users`; a reviewed unique canonical index is a later migration.

For any email with more than one canonical account match, regular users receive **no** `/history`, `/api/history`, `/api/scan-history`, or `/api/scans` rows, including rows with a `user_id`. The old startup migration used `LIMIT 1` to populate those IDs, so a populated ID cannot establish provenance for a collision. New startup runs no email-to-ID backfill. Logs record only aggregate withheld row counts, without addresses, QR data or account IDs.

For an account with a unique email, account reads include its own ID-bound rows and unbound legacy rows with that email. A row bound to another ID remains hidden even if its email matches. Access and portability requests use the same rule: a collision leaves the request `submitted` and returns no export. Erasure also stays `submitted` on a collision and does not delete another account's data.

Wallet read/write routes, referral status, and airdrop status return HTTP 409 on a collision. Profile and page scan counts show zero; the profile referral count shows zero. New QR risk analysis still runs, but a colliding account's email-keyed scan aggregate is not updated. Its new stable-ID history row is stored but remains hidden until ownership review. Unique accounts retain normal wallet access. The public leaderboard uses stable-ID scan rows only and omits accounts with colliding emails. Unbound legacy rows no longer count toward public rankings, even for a unique account.

Admin/owner RLS bypass is retained for existing administrative use, including admin scan views. Admin access must remain role gated. The hotfix does not alter public threat intelligence or QR analysis output.

## Residual risk and follow-up

Previously backfilled rows may have been assigned to the wrong ID. The hotfix withholds them when a current canonical collision is present, but it cannot prove provenance where the second account was removed or the email changed. An offline, access-controlled production backup audit is needed to identify and quarantine those rows. Do not infer ownership from email or run a blind repair on the live database.

`scans`, `scan_events`, wallets, referrals, and some fraud state remain email-keyed. They require a reviewed migration to stable account IDs. This hotfix blocks the direct collision paths while preserving the normal unique-owner path. It is not a replacement for the staged Phase 8 audit and migration.

Focused tests cover colliding sessions, concurrent requests, case/Unicode/IDNA collisions, ID-bound and legacy rows, privacy export/erasure refusal, normal unique-account reads, wallet behavior, and leaderboard attribution. No production database or external provider was accessed.
