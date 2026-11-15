# SafeScan incident response working runbook

**ATTORNEY REVIEW NEEDED.** This is a response checklist for the owner and engineers, not legal advice or a legal deadline chart. Counsel decides whether an event is a reportable breach and which notices apply.

## First hour: contain and preserve

1. The on-call owner appoints an incident lead and opens a restricted incident record. Record detection time, reporter, systems, suspected data categories and immediate actions. Keep personal details out of public issues and chat channels.
2. Preserve relevant Render deployment IDs, application logs, database snapshots, Cloudflare logs, Stripe webhook/event IDs and affected code commits before rotating or deleting evidence. Limit access to the incident team. Record who collected each copy and when.
3. Contain the specific path: disable the affected feature, revoke exposed API keys and sessions, rotate secrets, block an abusive client at the edge, or roll back the deploy. Do not erase evidence needed to determine scope. Confirm the old credential no longer works.
4. For scanner or uploaded-image incidents, identify whether QR payloads, URLs with query tokens, photos, wallet addresses, Go Ghost profiles, or account data reached a third party or logs. Check both current storage and backups. Do not infer a breach solely from a scanner error.
5. Engage qualified breach/privacy counsel and the insurer or incident-response firm if applicable. The owner decides customer and regulator communications with counsel.

## Investigation and recovery

- Maintain a timeline in UTC: first access, detection, containment, scope decisions, affected data, vendor notices, eradication, credential rotations, restoration and monitoring.
- Verify account ownership and access boundaries before extracting affected records. Query by stable user ID; treat email collisions as unresolved until reviewed.
- Reproduce the defect in an isolated environment using synthetic data. Add a regression test and a deployment check. Keep a list of exposed credentials and rotate them in every environment where they were valid.
- Reconcile Stripe subscriptions and payment actions with Stripe's signed event records; do not grant or remove access based on a redirect page.
- After recovery, monitor for recurrence, document the root cause and action owner, and update the data map, vendor register and privacy notice if the actual data flow differed.

## Notice decision worksheet

| Jurisdiction / rule | Starting source | Working deadline | Owner confirmation |
| --- | --- | --- | --- |
| Florida, if affected residents and statutory conditions apply | [Florida Statutes § 501.171](https://www.flsenate.gov/Laws/Statutes/2026/501.171) | The statute generally discusses notice within 30 days after a determination, with conditions and exceptions. Counsel must determine applicability and the trigger date. | Attorney pending |
| Other US states and federal sector rules | Relevant current statutes and regulator guidance | **Not populated.** Do not assume Florida's timing applies elsewhere. | Attorney pending |
| EU/EEA or UK, if applicable | Relevant regulator and statutory text | **Not populated.** Counsel must determine whether and when a supervisory-authority or individual notice is required. | Attorney pending |
| Contractual/vendor notices | Actual agreements with Render, Cloudflare, Stripe, Google, mail and storage providers | **Not populated.** Review executed contracts. | Owner + attorney pending |

## Draft communication fields (do not send without review)

- What happened and when it was discovered; what is known and uncertain.
- Categories of data involved and population affected, without unnecessary personal details.
- Actions SafeScan has taken, steps people can take, a working contact channel and next update date.
- The legal basis, recipients and timing for each required notice, confirmed by counsel.

The owner should rehearse this runbook with a tabletop exercise and record the outcome. No incident contact, 50-state deadline matrix, insurer or vendor notice requirement has been verified in this repository.
