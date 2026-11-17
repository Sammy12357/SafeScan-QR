# Compact text copy: visual check

Before is merged `37ab8f3` (#123); after is the additive compact-copy change. Both pages ran on isolated local servers with the same mocked **Plain QR** response for `https://sqafe.com/` and the Ember gradient. No production request or screened URL check was made. The animated PNG remains 279 px wide at 375 px and 480 px at wider breakpoints.

| Theme | Width | Before | After, ASCII default | After, compact selected |
| --- | ---: | --- | --- | --- |
| Dark | 375 | [before](before-dark-375.jpg) | [ASCII](after-ascii-dark-375.jpg) | [compact](after-compact-dark-375.jpg) |
| Dark | 768 | [before](before-dark-768.jpg) | [ASCII](after-ascii-dark-768.jpg) | [compact](after-compact-dark-768.jpg) |
| Dark | 1440 | [before](before-dark-1440.jpg) | [ASCII](after-ascii-dark-1440.jpg) | [compact](after-compact-dark-1440.jpg) |
| Light | 375 | [before](before-light-375.jpg) | [ASCII](after-ascii-light-375.jpg) | [compact](after-compact-light-375.jpg) |
| Light | 768 | [before](before-light-768.jpg) | [ASCII](after-ascii-light-768.jpg) | [compact](after-compact-light-768.jpg) |
| Light | 1440 | [before](before-light-1440.jpg) | [ASCII](after-ascii-light-1440.jpg) | [compact](after-compact-light-1440.jpg) |

The original ASCII copy remains selected by default. The compact Unicode option shows a smaller colored text QR below the unchanged animated PNG. The project's decoder read all six [compact preview captures](compact-dark-375.png), including the 279×232 mobile view; each used fixed-width text with line-height 1. [Metrics](metrics.json) show no page-level horizontal overflow at the captured widths. The screenshots are still captures; browser tests sample the PNG over time for motion.

`tests/test_qr_generator_motion_copy_browser.py` checks exact plain-text copy, rich clipboard line colors, paste into a rich editor, and opened styled HTML downloads for both text formats. The colored rich paste and HTML downloads decoded in Chromium. Raw `.txt` keeps characters only; a message app may change the font, line spacing, wrapping, or colors. A physical phone camera and external messaging apps were not tested.

Reproduce from this candidate with `python -m scripts.capture_ascii_compact_copy_evidence --baseline /path/to/37ab8f3-worktree --output docs/design/screenshots/ascii-compact-copy`.
