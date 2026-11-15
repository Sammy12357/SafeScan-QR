# Published legal-document source and change log

**ATTORNEY REVIEW NEEDED.** This is an engineering version registry. It does not establish that any clause is valid or that SafeScan has verified a legal contracting entity.

| Document | Version | Label in site | Source | Change |
| --- | --- | --- | --- | --- |
| Terms of Use | `v1.0` | May 2026 | `hackabull/legal_published/terms.v1.0.html` | Snapshot of the prior source constant, captured November 15, 2026. Past deployment text not independently verified. |
| Privacy Policy | `v1.0` | May 2026 | `hackabull/legal_published/privacy.v1.0.html` | Snapshot of the prior source constant with default contact email, captured November 15, 2026. |
| Cookie Policy | `v1.0` | May 2026 | `hackabull/legal_published/cookie.v1.0.html` | Snapshot of the prior source constant, captured November 15, 2026. |
| Terms of Use | `v1.1` | November 15, 2026 | `hackabull/legal_published/terms.v1.1.html` | Align age sentence and describe explicit reacceptance. Full terms remain subject to attorney review. |
| Privacy Policy | `v1.1` | November 15, 2026 | `hackabull/legal_published/privacy.v1.1.html` | Disclose agreement records and server age outcomes. Current contact email comes from `ADMIN_EMAIL`. Full policy remains subject to attorney review. |

Stable archive URLs use `/legal/documents/{terms|privacy|cookie}/{version}`. The current Terms and Privacy links serve `v1.1`; Cookie Policy still serves `v1.0`. Any future substantive edit must add a new file and version rather than modifying an archived file. `hackabull/legal_agreements.py` declares the active versions, and the sign-in flow records the two active versions. When those values change, an existing user is asked to reaccept at the next explicit sign-in.
