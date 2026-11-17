# ASCII motion QR as live text: visual check

Before is `origin/main` at `1116e49`; after is the current branch with the four-frame ASCII generator and copy instructions. Both pages ran on isolated local servers. The same mocked **Plain QR** response for `https://sqafe.com/` was used at each width and theme. No production request or screened URL check was made.

| Theme | Width | Before | After |
| --- | ---: | --- | --- |
| Dark | 375 | [before](before-dark-375.jpg) | [after](after-dark-375.jpg) |
| Dark | 768 | [before](before-dark-768.jpg) | [after](after-dark-768.jpg) |
| Dark | 1440 | [before](before-dark-1440.jpg) | [after](after-dark-1440.jpg) |
| Light | 375 | [before](before-light-375.jpg) | [after](after-light-375.jpg) |
| Light | 768 | [before](before-light-768.jpg) | [after](after-light-768.jpg) |
| Light | 1440 | [before](before-light-1440.jpg) | [after](after-light-1440.jpg) |

The after panel shows the animated ASCII QR as actual `<pre>` text with the Ember gradient, Copy ASCII QR, and Download .txt. The old image preview and Play motion button are absent. The screenshots are still captures; `tests/test_qr_generator_motion_copy_browser.py` verifies the four distinct text frames play automatically, each frame decodes at 375 and 768 px, and the copied characters stay exact in plain and rich paste. The rich paste retains the tested scan-ready styling; plain-text apps need the stated font and line spacing to scan.

At every captured width, the document width equaled the viewport width; the output and controls remained within the panel. The 375 px view includes a small-size notice. [Layout metrics](metrics.json) include the natural unscaled text width and its scaled on-screen width. Reproduce with `python -m scripts.capture_ascii_motion_text_evidence --baseline /path/to/origin-main-worktree --output docs/design/screenshots/ascii-motion-dom`.
