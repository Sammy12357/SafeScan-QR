# Go Ghost on-device automation release gate

Go Ghost currently provides a manual broker directory and local progress. The
server-side broker runner remains fixed off under
`GO_GHOST_BROWSER_AUTOMATION_AVAILABLE = False`. Running a browser extension on
the user's device does not by itself authorize automated access to a broker.

## Broker permission

Before adding an active search, form-filling, submission, or repeat-check recipe
for a broker, record:

1. The broker's current terms and applicable opt-out instructions, with the
   source URL and date reviewed.
2. The specific permission or agreement allowing SafeScan's proposed automated
   behavior in a commercial product, including whether an authorized family
   member may act for the data subject.
3. A walkthrough of the live removal flow using a test identity, with only
   sanitized fixtures committed to the repository. Never test on another
   person's record without permission.
4. The exact hosts, form fields, selectors, success conditions, human steps,
   and a way to disable the recipe when a site changes.

Until these items are satisfied, the broker stays in guided manual mode. A
user's attestation to help family does not override a broker's self-use rule.
PeopleConnect's suppression flow therefore remains self-only in SafeScan. Its
terms restrict the tool to personal, noncommercial use and prohibit scripts and
similar automated access. NeighborWho's terms also prohibit automated access.
These are examples of why the product must check each broker separately, not a
complete review of the 18 broker entries.

Sources reviewed November 14, 2026:

- [PeopleConnect terms](https://peopleconnect.us/terms-of-use/), sections 1, 2,
  and 5.
- [NeighborWho terms](https://www.neighborwho.com/terms-and-conditions/),
  restrictions on use.

## Extension implementation

Any future Manifest V3 extension must package both its interpreter and recipes
with the extension. Chrome Web Store policy expressly identifies an interpreter
running complex commands fetched from a remote server as a common violation.
The server may send data such as a disabled-feature flag, but must not supply
new executable recipe logic. Never use `eval`, `new Function`, remote scripts,
or a CAPTCHA-solving service.

Each navigation and extracted field must stay within the broker-specific
allowlist. A selector must match exactly one intended element or stop. Identity
selection, an ambiguous match, a CAPTCHA, and any attestation outside an
explicitly authorized meaning are handed to the person. Network errors and
site changes fall back to guided manual mode. Personal profile details and
listing URLs stay on the device; status sync contains only bounded state codes.

Source reviewed November 14, 2026:

- [Chrome Web Store Manifest V3 requirements](https://developer.chrome.com/docs/webstore/program-policies/mv3-requirements/).

## Release checklist

- The broker-specific permission record and sanitized flow fixtures are in the
  PR and have been reviewed.
- The extension requests only the broker hosts needed by released recipes.
- Tests cover off-domain navigation, ambiguous selectors, changed layouts,
  CAPTCHA handoff, no profile data in sync, and clean disable/fallback behavior.
- A human test in Chrome and Edge demonstrates the complete flow and records
  exactly what actions are still required from the user.
- Product copy distinguishes a submitted request, a user report, and a removal
  independently verified by a later search. It does not promise deletion or
  broker compliance.

This gate applies to automated broker interaction on any client, including a
future mobile WebView. It does not block official links, instructions, manual
opt-outs, local profile storage, or truthful progress tracking.
