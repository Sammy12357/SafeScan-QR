# Phase 5 input and ID preparation

This branch adds a pure-ASGI request-body limit before FastAPI parses JSON or
form fields. JSON content types receive a 64 KiB ceiling; other non-upload
bodies receive 16 KiB. Both declared `Content-Length` and actual streamed
bytes are checked. An oversized body returns 413 as soon as the limit is
crossed, without buffering the remaining chunks. Malformed or duplicate
`Content-Length` values return 400.

The existing scanner upload admission middleware still checks rate and
concurrency before reading upload bytes, applies a 15-second read deadline,
and counts actual streamed bytes. Its body ceiling is now capped at 10 MiB;
the default image-file ceiling remains 8 MiB. Both upload routes continue to
read the file with `MAX_QR_UPLOAD_BYTES + 1`, so only bounded file data reaches
the decoder. The new ASGI guard checks upload `Content-Length` as well.

Local email/password routes remain disabled in production. In developer/test
mode they now reject emails over 254 characters and passwords over 1,024
characters; the password hash/verify helpers enforce the password cap before
PBKDF2 too. `make_id()` now uses a 128-bit `secrets.token_urlsafe(16)` suffix
for new scan, report, data-request, and other generated IDs. Existing IDs
remain valid; this changes no database schema.

This is a **preparation branch**, not the complete Phase 5 release. Parser
hardening for SVG/PDF/images, email canonicalization and uniqueness migration,
free-text field schemas, regex audit, and frontend prototype-pollution review
remain. Integrate after the Phase 2 identity and Phase 3 ingress/rate-limit
gates, and resolve any overlapping auth and middleware edits before release.
