---
name: qr-decode-bench
description: Use when changing SafeScan camera capture, QR decoding, decode worker, or decoder dependencies. Compare read rate and latency against the QR corpus.
---

# QR decoding benchmark

Read `docs/plans/camera-scanning-v3.md` and current scanner code. That plan predates the approved opt-in auto-capture behavior; current user decisions take precedence.

1. Before changing decoding, run the applicable server or client benchmark in `scripts/qr_bench/` on the same corpus and save the result.
2. Afterward, rerun it under comparable conditions. Report read rate per category and p50/p95 decode time, including failures. Investigate any category regression.
3. Run focused camera controls and ambiguity tests. Check a physical phone when camera behavior or viewport layout changes.

## Invariants

- Manual capture remains the default. Live locating can guide without submitting; user-armed auto-capture may submit when its existing stability and single-code checks pass.
- Refuse distinct multiple payloads instead of guessing.
- Preserve the full-resolution first attempt and the server's time budget.
- Camera frames sent for consented fallback are decoded in memory, without storing the image.
- Keep decoder assets pinned and local to `static/vendor/`.
