# Legal-risk engineering baseline

Reviewed 2026-11-15 against `a2ce01b` and the user-supplied `SAFESCAN_LEGAL_RISK_PLAN.md`. This is a code and operations inventory, not a legal opinion or an assertion that any law applies to SafeScan. The [research log](research-log.md) records primary sources and their limits. The [attorney packet](attorney-packet.md) collects business facts and legal decisions that code cannot establish.

## Immediate engineering priorities

| Priority | Observed condition | Planned phase / acceptance evidence |
| --- | --- | --- |
| 1 | `/auth/confirm-age` accepts email and threshold from the request and is not called by the OAuth sign-in route. The existing compliance checklist says it is an enforced gate. | Phase 1: bind a neutral age screen to a server-held pending identity, use a server-selected threshold, prevent account creation on a failed check, and test the full sign-in path. Leave Auth0 tenant configuration review for the owner later. |
| 1 | A signed-in visit to `/pay/alpha/success` calls `record_alpha_subscription_purchase` without a verified Stripe event. | Phase 1: derive subscription access from signed Stripe webhooks or verified processor state, and test direct success-page visits. |
| 1 | The waitlist form stores an address and sends an email, while the site claims one-click unsubscribe. No suppression route or verified company postal address is present. | Phase 1: remove the unsupported claim immediately, implement a suppression path and consent record, and keep commercial sends off until a real postal address and sender identity are configured. |
| 2 | The stylesheet imports Orbitron from Google and the homepage loads Google sign-in code automatically. | Phase 1: serve the font locally; load sign-in code only at the authentication step where practical. Verify guest network requests in both themes. |
| 2 | Subscription purchase surfaces do not show complete recurring terms beside the payment action, and the Stripe portal configuration is unknown. | Phase 1: put verified terms and an unchecked billing-consent control at checkout; expose a cancellation route only after the live portal is tested. The owner must choose a refund position. |
| 2 | Scan results use `SAFE`; public threat listings lack a correction workflow. | Phases 2 and 5: describe observed checks and limits, record claim evidence, and add an evidence-backed dispute route. |
| 2 | `PyMuPDF==1.26.7` is in runtime dependencies and required notices have not been inventoried. | Phase 3: replace or commercially license it, verify exact dependency and bundled-asset licenses, and publish notices. |
| 2 | Privacy text promises retention and other practices that are not supported by an identified job or complete data-flow evidence. The Cookie Policy omits several current keys and lists an unused one. | Phase 4: connect data map, rights handling, retention, storage and vendor inventories to tested behavior; submit policy wording for attorney review. |
| 3 | Token and airdrop surfaces remain available without a single production-off control. | Phase 6: default all distribution-related functionality off pending specialist review. |

## Corrected assumptions from the supplied plan

- The Privacy Policy already mentions Google profile pictures and the in-memory camera retry. These claims need verification against production, rather than duplicate text.
- Optional first-party scanner performance counts exist and are gated by a browser consent choice. The banner's optional-analytics phrase therefore has some code support, although the Cookie Policy and storage inventory are incomplete.
- Go Ghost supports family subjects with an authority attestation. The user's later instruction explicitly preserves this option; broker-specific self-submission restrictions still apply.
- The 2024 FTC Click-to-Cancel rule was vacated. The [research log](research-log.md) cites the 2026 Federal Register notice and the continuing ROSCA obligation; the public billing terms must be checked against current applicable law.
- Whether SafeScan has a registered legal entity, which jurisdictions it targets, and which providers are enabled in production are not established by the repository.

## Register scope and limitations

`data-map.yaml` is a JSON-compatible YAML 1.2 engineering inventory generated from an isolated copy of the current SQLite schema. It lists every active table and column, with table-level source, purpose, recipient and retention notes; it is **not** yet a per-field privacy disclosure. The accompanying test detects schema drift. The [vendor register](vendor-register.md) inventories observed and possible outbound hosts, and the [browser storage inventory](storage-inventory.md) records keys found in source. Neither can establish production settings or contractual rights. The [claims register](claims-register.md) identifies public statements whose evidence or wording needs review.

No production personal records were read to create these registers. All public policy, terms, refund, and age-jurisdiction choices remain in the attorney packet for qualified counsel and owner review.
