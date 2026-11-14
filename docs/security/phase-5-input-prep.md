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

The parser pass adds `defusedxml` for SVG parsing and rejects DTDs, entities,
external references, excessive nesting, and oversized regex-consumed SVG
attributes. SVG path data is allowed to exceed 4,096 characters because the
basic renderer does not parse it with a regex and normal QR generators produce
long paths. Raster uploads are limited by detected format to single-frame
PNG, JPEG, or WebP; TIFF, EPS, and animated images are rejected before pixel
decode. Pillow decompression warnings are treated as errors. PDF pages are
preflighted at 2.5× against a 12-megapixel render ceiling, then converted from
the bounded RGB pixmap directly to a Pillow image without PNG re-encoding.
The existing five-page limit and killable decode worker still apply.

This is a **preparation branch**, not the complete Phase 5 release. Email
canonicalization and uniqueness migration, free-text field schemas, and the
remaining regex/frontend audit are separate work. Integrate after the Phase 2
identity and Phase 3 ingress/rate-limit gates, and resolve overlapping auth
and middleware edits before release.

Parser references: [defusedxml usage](https://github.com/tiran/defusedxml#readme),
[Pillow security guidance](https://pillow.readthedocs.io/en/stable/handbook/security.html),
and [PyMuPDF pixmap memory notes](https://pymupdf.readthedocs.io/en/latest/pixmap.html).
