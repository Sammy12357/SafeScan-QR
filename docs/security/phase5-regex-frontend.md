# Phase 5 regex and frontend audit

The owned Python regexes used for QR classification, wallet patterns, and
request validation were reviewed. They contain no nested quantified groups.
Decoded QR text is rejected above 4,096 characters before classification or
embedded-URL extraction, so a late malicious link cannot be silently ignored.
The crypto heuristic checks each bounded URL component separately; an
oversized direct call returns a high-risk signal. Other regex inputs from
legacy display fields and identifiers are capped before matching.

The custom Semgrep rules in `.github/security/semgrep-redos.yml` block common
nested Python regex quantifiers and dynamic JavaScript `RegExp` construction.
Semgrep 1.185.0 finds neither pattern in owned code and detects both in
adversarial probes. These rules are a guardrail, not a proof that every future
regex is linear; input limits and review remain necessary. Rule syntax follows
[Semgrep's rule-writing documentation](https://semgrep.dev/docs/writing-rules/rule-syntax/).

The owned frontend code has no untrusted recursive object merge. Go Ghost
progress keys originate from a fixed broker catalog, and the camera worker
spreads only internally constructed result objects. Local profile spreads do
not write attacker-selected keys into an existing prototype. Vendored JS is
outside this source audit and is not changed here. No frontend mutation was
warranted by this audit.

SVG attribute regexes in `qr_decode.py` are handled in the separate Phase 5
parser branch. Large SVG path data is not subject to the QR text limit.
