# Legal Phase 7 accessibility review

The work started from `origin/main` at `ad3e52a` and was rebased onto `068183c` after Phase 6 was released. An initial desktop-width axe run of 44 public views in dark and light mode found 87 serious or critical rule hits. The repeated causes were footer consent and link contrast, the login "Remember me" label, a contact note, and inline links in legal text that relied on color alone.

The new CI audit inventories public GET HTML routes and checks 49 route variants in both themes at 375 and 1440 CSS pixels (196 renders). It runs every axe 4.14.0 rule and fails on serious or critical findings. A separate keyboard audit checks focus containment and return focus in the menu, camera, scan result, wallet, and Go Ghost dialogs. These are automated browser checks, not a WCAG conformance audit.

The all-rules audit still reports moderate best-practice findings for heading order and region/main landmarks. They are recorded as known issues on `/accessibility` and need a separate template-wide cleanup and manual screen-reader review. They are not classified by axe as serious or critical.

Visual review used local mock data at 375, 768, and 1440 CSS pixels in both themes for the home, login, and contact pages plus the new accessibility statement. The home and statement captures were refreshed after rebasing onto Phase 6. The images below are representative; the full local matrix remains under `.cache/legal-phase7-*`.

| View | Before | After |
| --- | --- | --- |
| Home, light, 375 px | [Before](before-home-light-375.jpg) | [After](after-home-light-375.jpg) |
| Accessibility, light, 375 px | — | [After](after-accessibility-light-375.jpg) |
| Accessibility, dark, 1440 px | — | [After](after-accessibility-dark-1440.jpg) |
| Login, dark, 375 px | — | [After](after-login-dark-375.jpg) |
| Contact, light, 375 px | — | [After](after-contact-light-375.jpg) |

## Verification limits

- Physical camera behavior, native browser and operating-system controls, and mobile app screens are outside the automated browser audit.
- External Google/Auth0 and payment handoffs are outside the local mock environment.
- A complete screen-reader review across browser and device combinations has not been performed.
- Automated axe results do not cover every WCAG 2.2 AA criterion; continued manual review is required.
