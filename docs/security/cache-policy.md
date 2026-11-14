# Phase 3 verdict cache and HTML response policy

The old `qr_detect.analyze_url_payload()` path returned a `scan_results` row
for up to 24 hours before making reputation or redirect requests. A URL owner
could change the destination after a benign scan, leaving a stale SAFE result.
That shortcut is removed. The analyzer now runs the same live checks on every
call and writes no new verdict-cache rows. The `scan_results` table is left in
place so existing SQLite databases do not need a destructive migration.

The public URL scan endpoints already call `analyze_full_pipeline()` rather
than this legacy analyzer. This change does not alter their risk scoring or
verdict logic. It also does not alter the legacy analyzer's handling of a live
reputation failure: that separate coverage policy needs its own reviewed
change. A saved SAFE row can no longer hide such a failure or supply a verdict.

Dynamic HTML responses use `Cache-Control: private, no-store` and `Vary:
Cookie`, including guest pages that may embed a login challenge. Existing
`Vary` values are preserved. API JSON responses retain `no-store`, and
successful static assets retain their immutable-cache policy.
