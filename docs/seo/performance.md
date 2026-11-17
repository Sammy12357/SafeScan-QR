# Phase 5: homepage 3D load

## November 17, 2026: recover stalled model

The phone still starts automatically when at least half of its card enters the viewport. A trial of unconditional startup raised simulated mobile total blocking time from 142 ms to 1,428 ms in one comparable local Lighthouse run, so this release keeps viewport loading. The final candidate scored 81 with 118 ms total blocking time, close to the original score of 80 with 142 ms, and did not request Three.js before scrolling. These single runs are directional evidence, not field measurements.

When the browser requests reduced motion, the still image remains the default, with a visible **Play 3D model** button for people who want to opt in. If WebGL fails after the scene starts, the page reveals **Retry 3D model**; choosing it reloads the page and creates a fresh canvas context. The model's drag handler no longer captures Retry clicks. Initial download failures can still retry in place. The scanner does not depend on the hero model.

## November 2026 follow-up: start when the model is visible

The interaction-only loader below made the phone look frozen, particularly on touch screens where the full-card activation button had no visible label. The model now loads automatically when at least half of its card enters the viewport. It remains deferred when the card is offscreen, and people who prefer reduced motion keep the still image. A failed download leaves a visible retry control.

One comparable local Lighthouse 13.6.0 run per form factor used the current `main` tree and the candidate tree on the same isolated mock-mode server setup. These are single lab runs, not field performance measurements or a guarantee of the same scores in production.

| Version | Mobile score | Mobile LCP | Mobile TBT | Desktop score | Desktop LCP | Desktop TBT |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Interaction-only `main` | 82 | 4.44 s | 49 ms | 99 | 0.88 s | 0 ms |
| Starts when visible | 82 | 4.54 s | 38 ms | 90 | 2.01 s | 64 ms |

The desktop cost is accepted for an automatically moving hero. The mobile model starts when a person scrolls far enough to see it, so the initial mobile request still omits Three.js. Focused browser checks cover desktop and mobile activation, keyboard focus, reduced motion, failed downloads and retry, and the scanner flow. The [previous static screenshots](evidence/phase-5/after-static/dark/375/home.jpg) and [new active model screenshots](evidence/phone-model-autostart/active/dark/375/model.png) show the transition; the new model was also checked at 1440 px and in the light theme.

## Original change (historical)

The homepage now paints its existing still hero first. It requests `safescan-3d.js` and Three.js only after pointer interaction with the hero or keyboard activation of its labeled button. The still image remains visible until WebGL is ready. People who prefer reduced motion keep the still hero. The scanner does not depend on the model.

## Lighthouse results

Three runs per form factor used Lighthouse 13.6.0, headless Chrome 157, simulated throttling, and the same local mock-mode server setup on the same computer. The **before** tree was Phase 1 (`8d5d76f`, content-equivalent to merged `615bd34`); **after** was the Phase 1 tree with this performance change. The branch was subsequently rebased onto Phase 2 metadata without rerunning Lighthouse. Values below are medians.

| Environment | Mobile score | Mobile LCP | Mobile TBT | Mobile CLS | Desktop score | Desktop LCP | Desktop TBT | Desktop CLS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Local before | 66 | 11.17 s | 331 ms | 0.035 | 90 | 2.01 s | 38 ms | 0.020 |
| Local after | 82 | 4.54 s | 36 ms | 0.035 | 99 | 0.87 s | 0 ms | 0.020 |
| Earlier live baseline, different environment | 61 | 4.5 s | 1,090 ms | 0 | 51 | 2.4 s | 1,655 ms | 0.004 |
| Live after release, one run per device | 98 | 2.26 s | 93 ms | 0 | 100 | 0.50 s | 0 ms | 0.020 |

The local baseline varied substantially, especially mobile LCP (4.56–11.26 s) and desktop score (73–91). These are lab measurements with three runs, not field Core Web Vitals. The earlier live baseline includes production hosting and network conditions, so its difference from local results is **not** a measured production gain. The local candidate's mobile LCP remained above Google's 2.5 s good threshold.

The live rerun was taken on 2026-11-16 at 01:26 UTC using Lighthouse 13.6.0, headless Chrome 157, and simulated throttling. Mobile emulated a 412 × 823 Moto G Power (2022) at 150 ms RTT, 1,638 Kbps, and 4× CPU slowdown; desktop used 1350 × 940 at 40 ms RTT, 10,240 Kbps, and 1× CPU. Each row is a **single lab run**, and the earlier live baseline used different conditions. These results confirm that the released page omits `safescan-3d.js` and Three.js from initial requests, but do **not** establish a causal speed gain or field Core Web Vitals improvement. Desktop CLS rose from 0.004 in the earlier run to 0.020 in this run; Lighthouse attributed its shift to the cookie consent banner, and the observed value remained below the 0.1 good threshold.

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
