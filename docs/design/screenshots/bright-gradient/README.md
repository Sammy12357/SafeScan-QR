# Bright ASCII QR gradient controls

Before and after captures of the QR generator's gradient controls. The before build uses the saved-gradient baseline; the after build includes adaptive bright-gradient controls. In each capture, the top and bottom colors are `#F7E9FF` and `#FFE6A8`, then Custom gradient 1 is saved.

| Theme | 375 px | 768 px | 1440 px |
| --- | --- | --- | --- |
| Dark, before | [PNG](before-dark-375.png) | [PNG](before-dark-768.png) | [PNG](before-dark-1440.png) |
| Dark, after | [PNG](after-dark-375.png) | [PNG](after-dark-768.png) | [PNG](after-dark-1440.png) |
| Light, before | [PNG](before-light-375.png) | [PNG](before-light-768.png) | [PNG](before-light-1440.png) |
| Light, after | [PNG](after-light-375.png) | [PNG](after-light-768.png) | [PNG](after-light-1440.png) |

The baseline rejects the bright pair and leaves the slot empty. The updated UI shows a black-cell ASCII sample, explains that the QR's light gaps and quiet zone stay white, and enables the saved slot. The sample is decorative; scanner results are covered by the QR renderer tests. [Captured metrics](metrics.json) show document width equal to viewport width in all 12 captures.

Captured with local isolated app servers and headless Chromium. No production account or user data was used.
