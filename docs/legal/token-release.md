# Token feature release gate

**ATTORNEY REVIEW NEEDED.** Public token features default to unavailable. `TOKEN_FEATURES_ENABLED=true` must be explicitly set to show the token page, wallet connection, referral status, and eligibility details. Existing users can disconnect a previously linked wallet while the switch is off. The retired GET distribution route returns 410.

Distribution has a separate switch, `TOKEN_DISTRIBUTION_ENABLED=true`. The admin distribution form and route require a current owner session; the distribution engine also requires both token flags, its existing `AIRDROP_ENABLED` and mainnet gates, a strong admin secret, caps, and its default dry-run setting. CLI execution without an owner-authorized call is refused. Do not turn on any token or distribution switch solely because these controls exist.

Before enabling, the business owner and qualified counsel must decide the token's legal status, eligible jurisdictions, consumer disclosures, sanctions and tax duties, ownership of the mint and treasury, and operational key custody. Engineering has not implemented jurisdiction or sanctions rules by guesswork. Remove outdated token-promotional copy and document any new user-facing claim before release.
