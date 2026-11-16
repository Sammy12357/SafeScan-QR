# Security research log

## 2026-11-16 — Website Auth0 Google sign-in

| Primary source | Finding | Sqafe decision |
| --- | --- | --- |
| [Auth0 Python web-app guide](https://developer.auth0.com/resources/guides/web-app/flask/basic-authentication) | A server-rendered website uses a separate Regular Web Application, confidential client secret, callback URL, and authorization-code exchange. | Use a separate web client ID and secret; keep the Native app audience allowlist isolated. Store the secret only in Render. |
| [Auth0 connection selection guidance](https://support.auth0.com/center/s/article/Authenticating-users-through-a-specific-Connection-database-social-etc) | An authorization request can select `google-oauth2` explicitly. | Request only Google and reject every returned subject that does not begin with `google-oauth2|`. Reuse the verified Google suffix as the existing Sqafe account key; do not merge by email. |
| [Auth0 development-key warning](https://support.auth0.com/center/s/article/Warning-Occurs-About-Development-Keys-When-Tenant-Is-In-Production) | Default social test credentials are unsuitable for production. | The tenant's Google connection displays a dedicated Google client ID; confirm the connection's production ownership and runtime login before enabling the website flag. |

The web flow adds a one-use, browser-bound state cookie and server record, PKCE, nonce validation, exact client audience verification, verified email, and a 10-minute transaction expiry. The legacy direct Google endpoint is closed when website Auth0 is enabled. `tests/test_auth0_web_login.py` covers callback forgery, replay, audience, nonce, signature, account continuity, age eligibility, and logout. Live user login remains to be verified after Auth0/Render configuration.

Live guest-browser validation exposed two integration requirements before cutover: the original form submission did not navigate across the site's `form-action 'self'` policy, and Google's OAuth client rejected Auth0's `/login/callback` as an unregistered redirect. The website now starts login through a normal navigation link and permits only the configured Auth0 origin as an additional form-action target while the feature is enabled, so the logout POST can clear the provider session. A local Playwright click reached the Auth0 authorization URL after this change. The exact Auth0 callback must also be registered in the existing Google OAuth client before enabling the Render flag again.

## 2026-11-15 — QR lookalike-domain detection

| Primary source | Finding | SafeScan decision |
| --- | --- | --- |
| [Unicode UTS #39, confusable detection](https://www.unicode.org/reports/tr39/tr39-34.html#Confusable_Detection) and [Unicode 18 confusables data](https://www.unicode.org/Public/18.0.0/security/confusables.txt) | Visual similarity is wider than edit distance: cross-script letters and ASCII sequences can have the same confusable skeleton. Broad comparisons against every domain can produce false positives. | Pin the Unicode 18 table (SHA-256 `6ed3ee967c9dfdf6677d563c9985182fbc50a2efb7d6059cd57b2e2ce18f5b92`) and compare registrable labels only against selected protected brands. Warn separately about mixed Latin/Cyrillic or Greek scripts and invisible controls. This is a targeted LTR brand check, not a claim of full UTS #39 identifier-profile or whole-script classification. |
| [Unicode License v3](https://www.unicode.org/license.txt) | Commercial redistribution is allowed with the copyright and permission notice retained. | Ship the upstream notice beside the vendored data. |
| [Python IDNA codec docs](https://docs.python.org/3/library/codecs.html#encodings-idna) and [the `idna` project's documentation](https://github.com/kjd/idna/blob/master/README.md) | Python's built-in IDNA codec is IDNA 2003; the pinned `idna` package implements IDNA 2008 and UTS #46. The detector and outbound fetch must resolve the same A-label. | Use one `canonical_ascii_host` helper for URL validation, pinned-address fetching, local feed matching, and public threat-domain extraction. Keep the raw QR host's case for visual checks such as `paypaI.com`. |
| [Chromium IDN display policy](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/idn.md) | Browsers may show Unicode or punycode depending on spoof rules. | Show both forms as plain text in the scan result when they differ. Never use the displayed Unicode string as a link target. |

This phase does not inspect account display names. Those surfaces belong to the deferred identity work. The corpus under `tests/qr_corpus/edge_cases/url_threat_payloads.json` covers deceptive and ordinary internationalized hosts.

## 2026-11-14 — Phase 1: dependencies and CI

This entry records the supply-chain research used for the Phase 1 PR. The remaining security-plan phases need their own research and review before implementation.

| Topic and primary sources | Applies to SafeScan? | Action |
| --- | --- | --- |
| [Pillow 13.0.0 security release](https://github.com/python-pillow/Pillow/releases/tag/13.0.0) | Yes. Pillow decodes customer-uploaded images; the previous 11.3.0 pin predates many parser fixes. | Pin 13.0.0 and retain QR regression tests. |
| [python-multipart header-parsing advisory](https://github.com/advisories/GHSA-pp6c-gr5w-3c5g), [Starlette form-parsing advisory](https://github.com/advisories/GHSA-82w8-qh3p-5jfq) | Yes. FastAPI parses public upload and form requests. | Pin python-multipart 0.0.33 and Starlette 1.10.0. |
| [Starlette Host URL advisory](https://github.com/advisories/GHSA-86qp-5c8j-p5mr), [FastAPI release notes](https://fastapi.tiangolo.com/release-notes/) | Yes. SafeScan uses request URL paths in middleware; FastAPI 0.133.0 introduced Starlette 1.x support. This framework gap was absent from the original F4 package list. | **R-1, high, fixed in Phase 1:** pin FastAPI 0.162.7 and Starlette 1.10.0; rerun route tests. |
| [cryptography 50.0.2 changelog](https://cryptography.io/en/50.0.2/changelog/), [requests PyPI releases](https://pypi.org/project/requests/#history), [python-dotenv PyPI releases](https://pypi.org/project/python-dotenv/#history) | Yes. These libraries support authentication, signing, outbound requests, and configuration. | Pin cryptography 50.0.2, requests 2.34.2, and python-dotenv 1.2.4; rerun the full suite after the major cryptography upgrade. |
| [pytest advisory GHSA-6w46-j5rx-g56g](https://github.com/advisories/GHSA-6w46-j5rx-g56g) | Yes, in the test environment. The previous 9.0.2 pin is affected. | **R-2, medium, fixed in Phase 1:** pin pytest 9.0.3 in the dev lock. |
| [pip hash-checking mode](https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode), [uv pip compile](https://docs.astral.sh/uv/pip/compile/), [pip-audit usage](https://github.com/pypa/pip-audit#usage) | Yes. The former Docker build resolved dependency ranges at install time. | Generate runtime and dev locks with every resolved package pinned and hashed for Linux x86_64/Python 3.11. Docker and CI install with `--require-hashes`. `pip-audit` on both locks found no known vulnerabilities on 2026-11-14. |
| [Semgrep diff-aware scanning](https://semgrep.dev/docs/semgrep-ci/sample-ci-configs), [Gitleaks CLI](https://github.com/gitleaks/gitleaks#readme) | Yes. The repository already has findings, so new code should be gated without hiding existing code. | Compare Semgrep ERROR findings to the PR or push base. Scan every new commit with a SHA-verified Gitleaks binary. Review existing findings in their planned phases. |

### Static-analysis baseline review

[Bandit](https://bandit.readthedocs.io/en/latest/start.html) 1.9.4 reports 13 pre-existing medium findings under `hackabull`: ten `B608` dynamic SQL construction findings and three `B314` XML parser findings. The baseline records each file, line, rule, severity, confidence, description, and code digest. CI rejects any addition, removal, or changed snippet until the baseline is reviewed and updated.

The ten SQL findings interpolate only fixed SQL clauses or placeholder counts. Customer-supplied values are passed separately as SQLite parameters. This is a code-specific rationale, not a blanket exclusion; if a query changes, the baseline gate requires review. Two XML findings concern customer-uploaded SVG parsing; one parses a bundled static logo. **R-3, medium, Phase 5 follow-up:** switch the upload parser to `defusedxml` and remove the corresponding baseline entries after regression tests. The static logo parser can be reviewed at the same time.

Semgrep's `p/python`, `p/fastapi`, and `p/secrets` packs produced two pre-existing ERROR findings on the Phase 1 base. Diff-aware scanning blocks new ERROR findings; it does not declare the existing findings fixed. The current HTTP connection finding refers to fetching an explicitly HTTP customer URL through the pinned-address scanner, where upgrading the connection would change the destination being assessed. The XML finding is covered by R-3.

### Reproducing the locks

Use uv 0.13.8 and Python 3.11, targeting the Render Linux x86_64 image:

```sh
uv pip compile requirements.txt --python-platform x86_64-unknown-linux-gnu --python-version 3.11 --generate-hashes --output-file requirements.lock
uv pip compile requirements.txt requirements-dev.txt --python-platform x86_64-unknown-linux-gnu --python-version 3.11 --generate-hashes --output-file requirements-dev.lock
python scripts/check_dependency_locks.py
pip-audit --require-hashes -r requirements.lock
pip-audit --require-hashes -r requirements-dev.lock
```

The lock was cross-resolved on macOS, then checked against Linux wheel tags with a hashed pip dry run. The GitHub Linux runner is the final install and test check; no local Docker engine was available during preparation. Update both locks with any direct dependency change, then rerun the audit and full suite.
