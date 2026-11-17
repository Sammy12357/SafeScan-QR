# ASCII QR dark palette

The previous bright-gradient UI allowed `#F7E9FF` → `#FFE6A8` and showed a black-cell treatment. The updated controls keep the QR on white and adjust those choices to `#5D5760` → `#625840`, preserving their hues while reaching at least 7:1 contrast on white. Custom gradient 1 stores the adjusted pair.

| Theme | 375 px | 768 px | 1440 px |
| --- | --- | --- | --- |
| Dark, before | [PNG](../bright-gradient/after-dark-375.png) | [PNG](../bright-gradient/after-dark-768.png) | [PNG](../bright-gradient/after-dark-1440.png) |
| Dark, after | [PNG](after-dark-375.png) | [PNG](after-dark-768.png) | [PNG](after-dark-1440.png) |
| Light, before | [PNG](../bright-gradient/after-light-375.png) | [PNG](../bright-gradient/after-light-768.png) | [PNG](../bright-gradient/after-light-1440.png) |
| Light, after | [PNG](after-light-375.png) | [PNG](after-light-768.png) | [PNG](after-light-1440.png) |

[Captured metrics](metrics.json) confirm the white sample and no horizontal overflow at all six updated breakpoints. Captures used an isolated local server and headless Chromium; no production account or user data was used.
