# ASCII motion preview restoration: visual check

Before is merged `d22ff14` (#122); after is the candidate restoring the animated PNG preview. Both pages ran on isolated local servers with the same mocked **Plain QR** response for `https://sqafe.com/` and the Ember gradient. No production request or screened URL check was made.

| Theme | Width | Before | After |
| --- | ---: | --- | --- |
| Dark | 375 | [before](before-dark-375.jpg) | [after](after-dark-375.jpg) |
| Dark | 768 | [before](before-dark-768.jpg) | [after](after-dark-768.jpg) |
| Dark | 1440 | [before](before-dark-1440.jpg) | [after](after-dark-1440.jpg) |
| Light | 375 | [before](before-light-375.jpg) | [after](after-light-375.jpg) |
| Light | 768 | [before](before-light-768.jpg) | [after](after-light-768.jpg) |
| Light | 1440 | [before](before-light-1440.jpg) | [after](after-light-1440.jpg) |

The after view uses the earlier ASCII-textured PNG rendering with moving glyphs, dark gradient, and three textured finder corners. It autoplays with **Pause motion** available. There is one visible QR, followed by still/animated PNG downloads and Copy ASCII QR/.txt controls. The copied ASCII text is a separate still representation of the same QR payload; it does not preserve the PNG's exact glyphs, animation, or gradient.

All twelve captures have document width equal to viewport width; the restored preview is 279 px at 375 px and 480 px at wider breakpoints. [Metrics](metrics.json) record the visible image and control states. `tests/test_qr_generator_motion_copy_browser.py` samples APNG screenshots 400 ms apart to verify visible motion, checks QR decoding at mobile/tablet sizes, and checks reduced motion, pause/resume, and exact plain/rich clipboard plus .txt output. A physical phone camera was not tested.

Reproduce from this candidate with `python -m scripts.capture_ascii_motion_preview_evidence --baseline /path/to/d22ff14-worktree --output docs/design/screenshots/ascii-motion-preview-restore`.
