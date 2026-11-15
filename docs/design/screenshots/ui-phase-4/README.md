# Phase 4 error-page screenshots

Playwright Chromium captures from the baseline `83eed0a` and this branch after rebasing onto the shared UI tokens. The after views use locally rendered templates with a fixed sample request ID; no account or production data is used. The old 404 is a raw JSON response. The new 404 and signed-out 403/401 use the public page shell. Each capture is a full page at the stated viewport width.

| Width | Theme | 404 before | 404 after | Access page after |
| --- | --- | --- | --- | --- |
| 375 px | Dark | [Before](before-404-375-dark.png) | [After](after-404-375-dark.png) | [After](after-403-375-dark.png) |
| 375 px | Light | [Before](before-404-375-light.png) | [After](after-404-375-light.png) | [After](after-403-375-light.png) |
| 768 px | Dark | [Before](before-404-768-dark.png) | [After](after-404-768-dark.png) | [After](after-403-768-dark.png) |
| 768 px | Light | [Before](before-404-768-light.png) | [After](after-404-768-light.png) | [After](after-403-768-light.png) |
| 1440 px | Dark | [Before](before-404-1440-dark.png) | [After](after-404-1440-dark.png) | [After](after-403-1440-dark.png) |
| 1440 px | Light | [Before](before-404-1440-light.png) | [After](after-404-1440-light.png) | [After](after-403-1440-light.png) |
