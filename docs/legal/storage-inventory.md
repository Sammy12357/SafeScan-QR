# Browser storage inventory

Baseline: repository commit `ad3e52a` (Phase 1 merged), reviewed 2026-11-15. This records keys the application code reads or writes; it does not establish what a particular browser, Google, CDN, or hosting provider stores. Production environment settings and browser traffic still need verification. Server-side database and upload fields belong in `data-map.yaml`.

Phase 4 adds `tests/test_legal_privacy_gate.py` to compare first-party source-level keys and runtime cookie constants with the inventory and proposed Cookie Policy table, and to check a denylist of unreviewed tracker hosts. A guest browser smoke check covers keys observed in that flow. These gates do not replace a complete production browser traffic capture.

## First-party cookies

| Name | Set when / purpose | Browser lifetime | Attributes and source |
| --- | --- | --- | --- |
| `__Host-safescan_session` | Sign-in or restoration from a remember-me token; authenticates a SafeScan session. | `max_age` 24 hours; may be reissued on restoration. | `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`; `hackabull/sessions.py` `set_session_cookie`, `hackabull/config.py`. |
| `__Host-safescan_remember` | Sign-in with remember-me enabled or session restoration; carries an opaque token. The server stores a hash of it. | Default 30 days, configurable with `REMEMBER_ME_TTL_DAYS`; rotated when used. | `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`; `hackabull/sessions.py` `set_remember_me_cookie` / `validate_and_rotate_remember_me`. |
| `__Host-safescan_pending_age` | One-time age challenge after a verified Google web sign-in; holds only an opaque ticket, while minimal identity claims are temporarily server-side. | 10 minutes; deleted after an age decision. | `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`; `hackabull/routes_scan_auth.py`, `hackabull/routes_account.py`. |
| `__Host-safescan_adult_challenge` | One-time 18+ attestation form challenge for an adult-only feature. | 10 minutes; deleted after form submission. | `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`; `hackabull/routes_account.py`. |
| `__Host-safescan_adult_guest` | Opaque guest token for 18+ attested payment, token and Go Ghost pages. Server stores only its hash. | 24 hours; server record expires at the same time. | `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`; `hackabull/routes_account.py`, `hackabull/age_gate.py`. |

No application JavaScript cookie setter was found. Provider cookies, including cookies set by Google's sign-in frame/script, are **not verified** by this source audit.

## First-party `localStorage`

| Key | Data / purpose | Code-enforced lifetime | Source |
| --- | --- | --- | --- |
| `safescan_theme` | `light` or `dark` display preference. | Until browser/site data is cleared; no expiry in code. | `static/theme-init.js`, `static/sidenav.js`, `static/admin.js`. |
| `safeScanConsent` | Choice (`all`, `essential_only`, or `custom`), banner version and timestamp; controls banner display and opt-in scanner performance counts. Global Privacy Control overrides prior `all` choice in the browser, and `Sec-GPC: 1` coerces a server-received choice to `essential_only`. | Record remains until cleared; UI treats it as stale and asks again after 365 days. | `static/app-widgets.js` `storedConsentIsFresh`, `static/qr-camera.js`, `hackabull/routes_pages.py` `/api/consent`. |
| `safeScanConsentId` | ID returned by SafeScan's `/api/consent` response. | Until browser/site data is cleared; no expiry or read found in current client code. | `static/app-widgets.js`. |
| `phishproofAirdropProfile` | Local profile/rewards and wallet-related state, including an account email when available. Server state, not this value, controls verification. | Until browser/site data is cleared, or application code removes it. | `static/app-core.js` `getStoredAirdropProfile` / `setStoredAirdropProfile`. |
| `safeScanGoGhostV2:account:<encoded account id>` | Account-scoped Go Ghost subject profiles (including names, email, address, phone and birth year when entered), broker progress, consent and family attestations. | Until explicitly cleared or browser/site data is cleared; no automatic expiry found. | `static/app-go-ghost.js` `GO_GHOST_STORE_KEY`, `ghostSaveState`. |

## First-party `sessionStorage`

| Key | Data / purpose | Code-enforced lifetime | Source |
| --- | --- | --- | --- |
| `safeScanGoGhostV2:guest` | Guest Go Ghost subject profiles, broker progress, consent and family attestations; may contain the same personal fields as the account key. | Browser tab/session lifetime; application removes it when the signed-in Go Ghost workspace opens. | `static/app-go-ghost.js`, `static/app-go-ghost-ui.js`. |
| `safescan_sidenav_open` | Whether the navigation panel was open (`1` or `0`). | Browser tab/session lifetime. | `static/sidenav.js`. |
| `safescan:actor-email:<actor id>` | Admin-only cache of an audit actor's email address, reducing repeat admin API lookups. | Browser tab/session lifetime. | `static/admin.js`. |

## Legacy and policy-only keys

| Name | Current status | Source |
| --- | --- | --- |
| `safeScanGoGhostProfile`, `safeScanGoGhostProgress`, `safeScanGoGhostConsent` | Old, unowned `localStorage` data. The shared Go Ghost script removes these keys without reading or importing them. They may survive if that script never runs. | `static/app-go-ghost.js` `ghostEraseLegacyData`. |
| `safeScanReports` | Listed in Cookie Policy v1.0, but no application write or read was found in current source. It is removed from proposed v1.1's active-key table; historical browser copies remain unverified. | `hackabull/legal_published/cookie.v1.0.html`; source search. |

## Reconciliation needed

- Proposed Cookie Policy v1.1 now lists the first-party key families above, with their actual storage types. It remains a counsel-review draft until the production browser and network inventory, provider storage, and effective date are verified.
- The old `safeScanConsent` 12-month wording implied deletion. Proposed v1.1 distinguishes re-prompting after 365 days from browser removal; `safeScanConsentId` has no expiry in code.
- The banner (`templates/footer.html`) describes optional scanner performance counts. The identified opt-in path is in `static/qr-camera.js`, sent only when a fresh `all` choice exists and browser GPC is off. The server suppresses counts with `Sec-GPC: 1` and does not persist an `all` choice from such a request. Counsel must assess GPC's legal applicability; other analytics tooling and third-party cookies require runtime verification.
- Normal camera analysis uses in-memory frames; optional retained uploads use server storage (`hackabull/history.py` `persist_qr_upload`, `storage.py`) and are outside this browser-key list. Browser cache, provider cookies and browser permissions are also outside this list.
- The result cache is a server-side SQLite table, not browser storage. Phase 4 replaces its raw URL key with an HMAC and expires rows after 24 hours. Consent proofs in SQLite are retained for the policy's stated five-year period unless a documented legal hold suspends deletion. See `docs/legal/phase-4-privacy-operations.md`.

Update this inventory and the published Cookie Policy together whenever storage behavior changes. A browser test should enumerate cookies, `localStorage`, and `sessionStorage` after representative guest, sign-in, scan, Go Ghost, admin and payment flows.
