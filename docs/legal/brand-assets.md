# Brand and visual asset inventory

Checked 2026-11-15 against `static/`, templates, and the QR/model assets. This is an engineering inventory. The business owner and IP counsel still need to confirm SafeScan/SQAFE name clearance, ownership assignments, and rights in first-party art. Mentioning a platform by name to describe an integration does not imply its endorsement.

| Asset or use | Location | Status and decision |
| --- | --- | --- |
| SafeScan QR logo | `static/safescan-logo.svg`, navigation and generated QR codes | SafeScan-branded art. Retained. Owner should keep original design/assignment evidence; counsel should clear the name and mark. |
| SafeScan profile art | `static/safescan-profile-static.png`, `static/safescan-profile-animated.gif` | No in-repo reference found. Retained for potential external uses; owner should confirm original creation or license. Do not use these as proof of third-party endorsement. |
| Status icons | `static/icons/states.svg` | SafeScan UI icon sprite; no third-party wordmark observed. Owner should confirm provenance. |
| three.js | `static/vendor/three.module.js` | Code library, not a brand asset. MIT text retained at `static/vendor/THREE_LICENSE`. |
| zxing-wasm and ZXing-C++ | `static/vendor/zxing-wasm/3.1.6/` | QR decoder code and WebAssembly, not a brand asset. MIT/Apache texts already in the vendored directory. |
| WeChat QR model | `models/wechat_qr/` | Optional model, not a displayed logo. License text and third-party details retained in its directory. |
| Orbitron font | `static/fonts/` after Phase 1 merges | Google Fonts distribution under SIL OFL-1.1; exact OFL text retained in `third_party_licenses/Orbitron-OFL.txt`. Preserve its reserved font name and notice. |
| Solana logo bars and Solana Mobile fallback | Former homepage SVG, generated 3D texture, and `static/safescan-3d-fallback.png` | Removed because the repo did not contain a license or permission for these marks and the fallback image embedded Solana Mobile branding. Product support is described with plain text. |
| Google sign-in G | Two inline SVGs in `templates/login.html`, outside `static/` | Existing custom icon should be replaced by the official Google Identity Services rendered button in the identity phase; [Google's current guidance](https://developers.google.com/identity/branding-guidelines) says not to create a custom G icon. Avoid changing the authentication flow without an end-to-end sign-in check. |
| Platform and wallet names | Text throughout templates and scanner copy | Text descriptions only; no included third-party logos. Counsel should review marketing context and any implied affiliation. |

The third-party code and font notices are catalogued in [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md). Retain source and license evidence when adding any image, icon, font, or brand mark. Remove a third-party mark if the right to use it cannot be verified.
