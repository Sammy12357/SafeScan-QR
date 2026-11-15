---
name: safescan-legal-gate
description: Use when changing SafeScan public claims, legal documents, personal data, tracking, marketing email, billing disclosures, token features, licenses, or listing disputes. Guides the repository legal review gate, not legal advice.
---

# SafeScan legal gate

Check the actual code and deployed configuration before making a factual public statement. The registers in `docs/legal/` are working inventories, not approvals.

- For a new data field, storage key, cookie, recipient, host, or retention period, update `data-map.yaml`, `storage-inventory.md`, or `vendor-register.md` as applicable. Check the public Privacy and Cookie Policies against the behavior.
- For a public safety, performance, payment, token, or removal claim, add its evidence and owner to `claims-register.md`. Describe scan results as observations at scan time. Do not promise safety, removal, or token value.
- Keep marketing email disabled unless the sender has a verified legal name, postal address, consent, suppression, and one-click opt-out. Keep recurring billing disabled until identity, checkout terms, consent, webhook, portal, and receipts are verified.
- A public Terms, Privacy, or Cookie Policy edit needs a new version and effective date, retained prior snapshot, `legal-document-changelog.md` entry, and `attorney-packet.md` review row. Record whether acceptance or notice must change.
- Run focused tests plus `python -m pytest tests/test_legal_gate_*.py tests/test_legal_data_map.py -q`. Review `scripts/check_legal_document_changes.py` and the PR template. Escalate legal interpretations and ownership, licensing, billing, token, or dispute policy decisions to qualified counsel; mark drafted public legal text **ATTORNEY REVIEW NEEDED**.

The user's current instructions govern scope and authorization. Do not call these engineering checks a legal-compliance certification.
