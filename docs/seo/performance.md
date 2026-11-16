# Phase 5: homepage 3D load

## Change

The homepage now paints its existing still hero first. It requests `safescan-3d.js` and Three.js only after pointer interaction with the hero or keyboard activation of its labeled button. The still image remains visible until WebGL is ready. People who prefer reduced motion keep the still hero. The scanner does not depend on the model.

## Lighthouse results

Three runs per form factor used Lighthouse 13.6.0, headless Chrome 157, simulated throttling, and the same local mock-mode server setup on the same computer. The **before** tree was Phase 1 (`8d5d76f`, content-equivalent to merged `615bd34`); **after** was the Phase 1 tree with this performance change. The branch was subsequently rebased onto Phase 2 metadata without rerunning Lighthouse. Values below are medians.

| Environment | Mobile score | Mobile LCP | Mobile TBT | Mobile CLS | Desktop score | Desktop LCP | Desktop TBT | Desktop CLS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Local before | 66 | 11.17 s | 331 ms | 0.035 | 90 | 2.01 s | 38 ms | 0.020 |
| Local after | 82 | 4.54 s | 36 ms | 0.035 | 99 | 0.87 s | 0 ms | 0.020 |
| Earlier live baseline, different environment | 61 | 4.5 s | 1,090 ms | 0 | 51 | 2.4 s | 1,655 ms | 0.004 |

The local baseline varied substantially, especially mobile LCP (4.56–11.26 s) and desktop score (73–91). These are lab measurements with three runs, not field Core Web Vitals. The earlier live baseline includes production hosting and network conditions, so its difference from local results is **not** a measured production gain. A live rerun after release is needed. Mobile LCP remains above Google's 2.5 s good threshold in the local candidate.

The old page requested both `safescan-3d.js` and the 1.27 MB Three.js module during initial navigation in all six local baseline reports. Neither was requested during initial navigation in the candidate reports. The 3D scene still loads after intent; this moves its CPU cost to that interaction, so real-device responsiveness during activation should be checked before release.

## Browser and visual checks

`python -m pytest tests/test_seo_performance_browser.py tests/test_css_spacing_tokens.py tests/test_seo_foundation.py -q` passed: **24 tests**. The browser checks cover no initial model request, pointer and keyboard activation, arrow-key focus, reduced motion, a guest Wi-Fi payload result, a mobile-width guest scan without model activation, and no console errors on the successful path.

Playwright Chromium captured full-page home screenshots at 375 px and 1440 px in both themes. Baseline and static screenshots used reduced motion; the old page still rendered WebGL under that preference, while the candidate correctly uses a still hero. Active screenshots used normal motion after pointer activation. The active scene retains the earlier appearance. The static light-theme hero uses the existing CSS phone model and is visually approximate; the QR grid differs from the WebGL art.

| Theme / width | Before | After, still | After, active 3D |
| --- | --- | --- | --- |
| Dark / 375 | [View](evidence/phase-5/before/dark/375/home.jpg) | [View](evidence/phase-5/after-static/dark/375/home.jpg) | [View](evidence/phase-5/after-active/dark/375/home.jpg) |
| Dark / 1440 | [View](evidence/phase-5/before/dark/1440/home.jpg) | [View](evidence/phase-5/after-static/dark/1440/home.jpg) | [View](evidence/phase-5/after-active/dark/1440/home.jpg) |
| Light / 375 | [View](evidence/phase-5/before/light/375/home.jpg) | [View](evidence/phase-5/after-static/light/375/home.jpg) | [View](evidence/phase-5/after-active/light/375/home.jpg) |
| Light / 1440 | [View](evidence/phase-5/before/light/1440/home.jpg) | [View](evidence/phase-5/after-static/light/1440/home.jpg) | [View](evidence/phase-5/after-active/light/1440/home.jpg) |

The full-card activation button is visually transparent but has an accessible name and the site's visible keyboard focus ring. Enter or Space loads the model; focus then moves to the labeled canvas, where arrow keys rotate it. This has been checked with Chromium keyboard automation, not physical VoiceOver. The loader leaves the still hero visible until the renderer marks the scene ready, avoiding a blank transition.
