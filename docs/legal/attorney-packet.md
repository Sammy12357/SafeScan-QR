# Attorney review packet — Phase 0 baseline and later release gates

## Current engineering status (2026-11-15)

**ATTORNEY REVIEW NEEDED.** This section distinguishes the historical Phase 0 observations below from later engineering work. It does not approve public policies or establish the site's legal status.

- Phase 1 is merged: server-controlled account and adult age checks, self-hosted Orbitron, consent/suppression controls, and account-bound Stripe checkout and verified-event entitlement are implemented. Marketing email remains disabled without a real legal name and postal address. Card checkout remains disabled without verified business, Stripe, email, and refund settings. Sam chose: “No refunds after a billing period starts”; code preserves the required-by-law exception. The old Stripe Payment Link still must be disabled before card checkout opens.
- Phase 2 is a separate draft: bounded scan and QR claims, versioned Terms and Privacy snapshots, recorded acceptance and reacceptance. Its public legal text, effective date, governing-law and dispute clauses, entity identity, and matching mobile client need review before release.
- Phase 6 is merged: public token features and distribution default to off, and existing users can disconnect a linked wallet while features are off. Do not turn on either switch without owner authorization and specialist review.
- Phases 3–5 and 7 are separate engineering drafts or in progress: dependency/asset notices, privacy operations, public listing disputes, and accessibility. Their tests and internal documents do not prove production configuration or legal sufficiency. In particular, the Phase 3 license review must reconcile bundled native code and IP ownership, and Phase 4 retention needs operator evidence.
- Phase 8 adds CI source checks, a PR checklist, a legal-document change log and a project skill. The data-map check verifies table/column presence and table-level metadata; it does not establish a per-field purpose, recipient, or retention rule or generate the public policy. Source checks can catch specified regressions; they cannot establish production network traffic, vendor contracts, deletion from backups, the accuracy of every claim, or accessibility conformance. Recheck this packet as each draft merges.

### Decisions for the owner and qualified counsel

| Decision | Evidence to provide or review | Release boundary |
| --- | --- | --- |
| Real contracting entity, address, code/domain ownership, and trademark rights | Formation and assignment records; proposed Terms name and notice address | Do not call placeholders a real counterparty. |
| Terms, Privacy and Cookie Policy, including refund, arbitration, liability and international-transfer wording | Versioned snapshots, data map, actual production settings and provider contracts | Approve text and effective dates before publication of revised terms. |
| Marketing email | Verified legal sender name and postal mailing address; delivery and unsubscribe evidence | Leave commercial updates disabled until complete. |
| Card subscription | Stripe product, portal, checkout disclosures, receipt settings, disabled old Payment Link, and chosen refund wording | Leave new checkout disabled until all settings are verified. |
| Runtime and asset licenses | Phase 3 license manifest, native wheel notices, proprietary root-license decision, brand rights | Review before Phase 3 merge or any distribution of new assets. |
| False-positive listing process | Phase 5 dispute route, evidence and retention, response staffing | Review before presenting disputed public listings as adjudicated fact. |
| SQR token and airdrop | Phase 6 off-switch design, actual distribution history and planned jurisdictions | Keep features and distribution off pending specialist counsel and owner authorization. |

The entries below retain the original Phase 0 baseline for context. Their “current” language refers to that earlier code review, not necessarily to merged Phase 1 or draft phases.

## Phase 6 token controls — November 15, 2026

**ATTORNEY REVIEW NEEDED.** Token and airdrop features now default to unavailable. Existing wallet holders retain a disconnect path. Distribution needs a separate explicit production flag and an owner session, while the old GET trigger is retired. The controls do not establish that a token or airdrop may lawfully launch. Review the mint and treasury ownership, jurisdictions, sanctions, tax treatment, product claims, and any required disclosures before either switch is enabled. See `docs/legal/token-release.md`.

## Phase 7 accessibility statement — November 15, 2026

**ATTORNEY REVIEW NEEDED.** The proposed `/accessibility` page states a WCAG 2.2 AA target, identifies the remaining heading/landmark issues plus unverified screen reader, hardware, third-party handoff, and mobile-app coverage, and gives a contact path for barriers. It does not claim full conformance. Counsel and the business owner should review this statement and how feedback is handled before treating it as an approved legal disclosure.

**ATTORNEY REVIEW NEEDED.** Internal briefing, not legal advice or approved public policy. Prepared 2026-11-15 from code baseline `a2ce01b` and the supplied `SAFESCAN_LEGAL_RISK_PLAN.md`. It records questions and evidence for qualified counsel and the business owner. No legal text was published or approved by creating this packet.

## Public documents and review queue

| Item | Current source | Decision or verification needed | Owner |
| --- | --- | --- | --- |
| Terms of Use, currently `v1.0` / May 2026 | `hackabull/admin_data.py:627-651`; `hackabull/config.py:159-160` | Identify the actual contracting entity and contact address; review minimum age, Florida governing law, AAA arbitration, class waiver, liability cap, 30-day change notice, and whether version/acceptance records match deployment. | Sam + attorney |
| Privacy Policy, currently `v1.0` / May 2026 | `hackabull/admin_data.py:570-625` | Reconcile collection, data flows, retention, rights, international transfers, provider sharing, and the DPO statement with real operations and contracts. The policy already lists Google profile picture and optional scanner analytics; do not treat those as missing merely because the plan does. | Sam + privacy counsel |
| Cookie Policy | `hackabull/admin_data.py:654-670` | Audit cookies, local storage, Google sign-in assets, first-party telemetry, and any deployed production services; assess consent language and retention. | Engineering + privacy counsel |
| Marketing/waitlist disclosure and email | `templates/footer.html:11`; `hackabull/routes_pages.py:289-310` | Obtain a real company postal address; decide sender identity and marketing scope; implement a working opt-out and suppression process. Current “one click” claim is unsupported. | Sam + engineering + attorney |
| Alpha subscription, cancellation, and refunds | `templates/plans.html:26`; `hackabull/routes_pages.py:493,534-615` | Decide refund position; verify Stripe product, renewal, checkout and customer portal settings; disclose recurring terms and cancellation before payment. The success page currently records a purchase on page visit and requires engineering correction. | Sam + engineering + payments counsel |
| Go Ghost authorization and limits | `hackabull/go_ghost_status.py:169-223,293-300`; `hackabull/routes_pages.py:174-181` | User expressly chose to allow family submissions with an attestation. Review whether and how a family member can authorize the requester, which brokers require self-submission, what evidence to retain, and how to avoid promising removal or legal services. The attached plan says self-only; that instruction must be reconciled with the later user decision. | Sam + attorney |
| Public threat listings and verdicts | `templates/index.html:67,145-146,188`; `hackabull/routes_pages.py:411`; `/malicious-database` | Approve risk language, evidence standards, dispute/correction channel, and delisting process for false positives. See `claims-register.md`. | Security lead + attorney |
| SQR token, wallets, and airdrop | `templates/plans.html:24-25`; `templates/index.html:292-293`; `hackabull/admin_data.py:642-643` | Confirm whether any distribution is planned or has occurred. Specialist counsel to assess jurisdictions, eligibility, sanctions, tax, securities, money transmission, age restrictions, and marketing claims before any rollout. | Sam + specialist counsel |
| Third-party code, assets, and trademark | `requirements.txt` (`PyMuPDF==1.26.7`); `hackabull/qr_decode.py:592-603`; fonts/assets | Review PyMuPDF licensing and any replacement, third-party notices, font use, asset ownership, and SafeScan/SQAFE name and logo clearance. | Engineering + IP counsel |
| Accessibility statement and claims | Current templates/styles; future WCAG audit | Review any public conformance statement against a tested scope and remediation record. Do not claim full WCAG conformance solely from automated checks. | Engineering + accessibility counsel |

## Facts and gaps counsel should see first

1. The live legal text is embedded as HTML constants in `hackabull/admin_data.py`, with version/date constants in `hackabull/config.py`. The version history route (`hackabull/routes_pages.py:328-330`) needs to be checked against every actually published text revision. Any public policy or terms rewrite needs a version and effective date, archived prior text, and an acceptance/notice decision.
2. The Privacy Policy promises two-year inactive account deletion and five-year consent-record retention (`hackabull/admin_data.py:590-592`). No deletion scheduler was established in the Phase 0 code review. These are claims requiring operational evidence or revision.
3. The policy states that EU data transfers are intended to use Standard Contractual Clauses and that a DPO will be appointed at 5,000 EU users (`hackabull/admin_data.py:616-625`). Counsel should evaluate these statements against actual vendor agreements and applicable law; the numeric threshold should not be treated as a legal safe harbor.
4. The site already offers privacy request routes (`hackabull/routes_pages.py:763-834`), but end-to-end erasure across every table, backup, vendor, and log has not been verified. The accompanying data map and storage inventory should be completed before affirming coverage.
5. The QR scanner's optional first-party performance counters are real and consent gated in current code (`static/qr-camera.js`; `hackabull/routes_scan_telemetry.py`). The data inventory should verify deployed behavior and precise retention. Other analytics or provider statements require configuration and network review.
6. The current Go Ghost implementation supports self and family subject slots with a recorded family-authority attestation, and disallows family status updates for a broker group that requires self-submission (`hackabull/go_ghost_status.py:169-223,293-300`). It does not authorize blanket family submissions to every broker.
7. The Alpha payment success route calls `record_alpha_subscription_purchase(request)` when visited (`hackabull/routes_pages.py:606-615`). Counsel should review public representations after engineering changes entitlement to verified payment events.

## Decisions and materials needed from Sam

- **Entity and ownership:** legal name, formation jurisdiction, registration/good-standing proof, owners, code/domain assignment, and the business contact to name in the Terms and policies. Do not invent an LLC or use an unverified company name.
- **Postal address:** valid physical mailing address for commercial emails and legal notices. Supply it through configuration; do not invent one. Keep commercial email disabled until the address and opt-out mechanism are working.
- **Subscriptions:** the intended refund rule, cancellation route, Stripe dashboard/product/portal screenshots, whether Solana payments recur or are one-time, and the exact benefits actually available today.
- **Geography and age:** countries deliberately targeted, intended treatment of minors for scanning versus account, payment, wallet, airdrop, and Go Ghost features. Counsel should decide the lawful thresholds; the current age route accepts caller-supplied values (`hackabull/routes_account.py:245-267`).
- **Go Ghost family use:** confirm the user's family-with-attestation direction; specify the authorized relationships and any evidence or revocation procedure counsel requires. Preserve broker-specific self-submission limits.
- **SQR:** whether token distribution is planned, actual chain/contract and any past distributions, eligible territories, marketing channels, and specialist counsel contact.
- **Vendors and operations:** executed data-processing agreements, hosting region, Web Risk and any other provider agreements, mail provider, logs/backups retention, actual analytics tools, and incident contact.
- **Brand and assets:** trademark searches/registrations, logo/font/image licenses, third-party software inventory, and any commercial PyMuPDF license if one exists.

## Primary-source starting points

- [FTC CAN-SPAM compliance guide](https://www.ftc.gov/business-guidance/resources/can-spam-act-compliance-guide-business): commercial-email identity, postal-address, and opt-out requirements; counsel must assess which SafeScan messages are commercial versus transactional.
- [FTC COPPA FAQ](https://www.ftc.gov/business-guidance/resources/complying-coppa-frequently-asked-questions): child-data issues; counsel must assess actual knowledge, audience, and product-specific age gates.
- [FTC negative-option policy statement](https://www.ftc.gov/system/files/documents/public_statements/1598063/negative_option_policy_statement-10-22-2021-tobureau.pdf): recurring-billing disclosure and consent starting point; confirm current federal and applicable state rules before drafting.
- [W3C WCAG 2.2 Recommendation](https://www.w3.org/TR/WCAG22/): technical accessibility criteria, not a legal compliance determination.

The research log should record source access dates and jurisdictional applicability. Counsel should verify the current text of statutes, regulations, and agency guidance before approving public language. The separate `claims-register.md` records product statements needing code, operational, or business evidence.
