# Phone model recovery visual evidence

Each comparison shows the hero model card from `origin/main` (`32cf481`) on the left and the candidate worktree on the right. The browser reports reduced motion, so the base shows its static fallback and the candidate shows the manual **Play 3D model** control.

| Viewport | Dark | Light |
| --- | --- | --- |
| 375 × 812 | [Compare](compare-dark-375.jpg) | [Compare](compare-light-375.jpg) |
| 768 × 900 | [Compare](compare-dark-768.jpg) | [Compare](compare-light-768.jpg) |
| 1440 × 900 | [Compare](compare-dark-1440.jpg) | [Compare](compare-light-1440.jpg) |

After manual Play: [375 px light](active-light-375.jpg) · [1440 px dark](active-dark-1440.jpg).

## Capture method

On 2026-11-16, Chromium in Playwright loaded two local `uvicorn` mock servers with isolated data and no inherited service credentials. The base server used a temporary `git archive origin/main`; the candidate server used this worktree. Contexts used device scale 1, `prefers-reduced-motion: reduce`, and `safescan_theme` in local storage. Images are element screenshots of `.spline-showcase`, paired into JPEGs at quality 82. Active captures followed a click on **Play 3D model** and a one-second render wait.

The candidate button is visible and clear at all six sizes and themes; card dimensions match the base. The active canvas changed 3,078 pixels at 375 px and 7,191 pixels at 1440 px across one second, with no page errors. At 375 px, the caption covers the lower portion of the phone and QR artwork in both the base fallback and active candidate; this is an existing mobile layout treatment.
