# ASCII motion QR: copyable text visual check

Before is `origin/main` at `d18eb83`; after is the candidate. Both pages used an isolated local server and the same mocked **Plain QR** response for `https://sqafe.com/`, generated locally with the Ember gradient. No screened URL check or production request was made. Captures show the generator panel after selecting **ASCII motion QR**.

| Theme | Width | Before | After |
| --- | ---: | --- | --- |
| Dark | 375 | [before](before-dark-375.jpg) | [after](after-dark-375.jpg) |
| Dark | 768 | [before](before-dark-768.jpg) | [after](after-dark-768.jpg) |
| Dark | 1440 | [before](before-dark-1440.jpg) | [after](after-dark-1440.jpg) |
| Light | 375 | [before](before-light-375.jpg) | [after](after-light-375.jpg) |
| Light | 768 | [before](before-light-768.jpg) | [after](after-light-768.jpg) |
| Light | 1440 | [before](before-light-1440.jpg) | [after](after-light-1440.jpg) |

The candidate adds a copyable text QR beneath the animated preview. No page-level horizontal overflow or clipped controls appeared at any captured width. At 375 px, the default 13 px text fits its 261 px available width with a 258 px `<pre>`; the internal paper does not scroll. Forcing 16 or 18 px makes the paper scroll horizontally and cuts the visible QR: [16 px](text-dark-375-font16.png), [18 px](text-dark-375-font18.png).

The project's `hackabull.qr_decode.decode_qr_image` decoded all six candidate [text QR captures](text-dark-375.png), including 375 px at DPR 1, to `https://sqafe.com/`. It also decoded the [375 px DPR 2 text capture](text-dark-375-dpr2.png), the [active APNG at 375 px DPR 1](active-apng-frame.png), and the [active APNG at 768 px DPR 1](active-apng-768-dpr1.png). Four distinct browser-rendered [APNG phases at 375 px DPR 2](active-apng-375-dpr2-phase0.png) each decoded to the same URL ([1](active-apng-375-dpr2-phase1.png), [2](active-apng-375-dpr2-phase2.png), [3](active-apng-375-dpr2-phase3.png)). The motion control was active during these captures.

OpenCV's QR decoder missed some scaled 375 px screenshots that the project's decoder read; that does not establish a scanning failure. A physical phone camera was not tested. [Layout measurements](metrics.json) and the screenshots document this browser check.
