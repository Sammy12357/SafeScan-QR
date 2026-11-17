# Sqafe indexing handoff

**Reviewed:** 2026-11-17. **Canonical origin:** <https://sqafe.com>. This checklist records what the public site, repository, and owner-provided Search Console screenshots show, then separates the remaining account work. The screenshots establish indexation for three inspected URLs, not a sitewide indexed-page count or a ranking position.

## What is already live

| Check | Observed result |
| --- | --- |
| `https://safescan-qr.onrender.com/`, `/learn`, and `/plans?x=1` | Public HTML routes issue a single `301` to the same path and query on `https://sqafe.com`. `GET` and `HEAD` are covered. |
| `https://www.sqafe.com/learn` and `http://sqafe.com/learn` | A single `301` leads to `https://sqafe.com/learn`. A combined HTTP and alternate-host request may take an additional edge hop. |
| `https://sqafe.com/robots.txt` and `/sitemap.xml` | Both return `200`; the sitemap and its robots reference use the canonical origin. |
| Six sitemap pages | `/`, `/about`, `/learn`, two QR safety guides, and `/contact` return `200` with `index, follow` and self-referencing canonicals. The homepage raw HTML contains WebSite and Organization JSON-LD. |
| Old Render host service routes | API, health, static assets, and private routes remain available for existing clients. Private HTML is marked `noindex, follow`; unknown routes return `404`. The old-host robots and sitemap files return `200` with canonical sitemap URLs. |
| GitHub repository website | The repository homepage field points to `https://sqafe.com`; its README already links to the canonical site. |
| Google Search Console URL Inspection | Owner screenshots show `https://sqafe.com/`, `/about`, and `/learn` as “URL is on Google” and “Page is indexed.” Google-selected canonicals are not visible in those screenshots. |

The brief's reported `302` redirect is no longer reproducible on the reviewed public pages. The application already implements the permanent redirect in `hackabull/seo.py` and `hackabull/app_module.py`; a second host-wide redirect would interfere with old-host API and session clients. The old-host robots response does not duplicate an indexable HTML page, and robots rules apply to the host and protocol that serve them. Keep the redirect limited to the reviewed public HTML routes unless an integration audit supports a broader move.

The sitemap deliberately excludes `/plans`, `/malicious-database`, `/generate-qr`, and other pages currently marked `noindex, follow` pending content and claim review. Do not request indexing for them while that policy remains. There is no active token-airdrop offer or contract address in the reviewed homepage HTML. The existing FAQ describes token features as unavailable.

## Owner actions in Google Search Console

Repository records in [the search visibility checklist](offpage.md) say the `sqafe.com` **Domain property was verified through Cloudflare DNS** and `https://sqafe.com/sitemap.xml` was submitted successfully on 2026-11-15. Those account states were owner-reported. The 2026-11-17 owner screenshots show URL Inspection results for the homepage, `/about`, and `/learn`, so the brief's claim that no `sqafe.com` URL is indexed is false. The screenshots do not show Google's selected canonicals or a complete Page indexing report. The reported difficulty finding Sqafe for its brand query should be investigated with Search Console performance data rather than treated as a sitewide indexing block.

- [ ] Confirm the Domain property remains verified and the sitemap shows a successful fetch. Keep its DNS verification record. Do not submit a second sitemap just because a deployment occurred.
- [ ] In **URL Inspection**, inspect `/contact` and both guide URLs, then expand the results for the already indexed homepage, `/about`, and `/learn`. For each of the six current sitemap URLs, record the inspection date, Google-selected canonical, indexing state, last crawl, and any stated block or error. Use the live test where needed. Compare the exact URLs in the [current sitemap](https://sqafe.com/sitemap.xml); the sitemap can change after a release.
- [ ] In **Performance → Search results**, choose **Web** and filter for the exact query `sqafe`. Record the date range, country, device, impressions, clicks, and average position. This diagnoses brand visibility; it is separate from whether a URL is indexed. Record “no data” as such if the report has not accumulated enough data.
- [ ] If an eligible canonical page is not indexed, use **Request Indexing** for the affected URLs after resolving any reported issue. The request is a crawl hint, not an indexation guarantee. Review the **Page indexing** and **Sitemaps** reports after processing; distinguish discovered, crawled, duplicate, and blocked states before changing code.
- [ ] Try to add and verify the old Render host as a URL-prefix property in the same Search Console account. Inspect the old homepage and guide URLs there and record Google's selected canonical. If both properties are verified and Google's move eligibility checks pass, submit **Change of Address** for the host move. The existing `sqafe.com` Domain property alone does not establish ownership of the Render subdomain. Check the [available verification methods](https://support.google.com/webmasters/answer/9008080) in that account; do not assume that a tag on the redirected canonical homepage or a file on the new host verifies the old host. If old-host verification is unavailable, keep the permanent redirects and use the new property's indexing reports.
- [ ] Save dated screenshots or exports of the relevant inspection and indexing reports in private owner records. Do not put verification tokens or account credentials in the repository.

Google's [URL Inspection and recrawl guidance](https://developers.google.com/search/docs/crawling-indexing/ask-google-to-recrawl), [site move guidance](https://developers.google.com/search/docs/crawling-indexing/site-move-with-url-changes), and [Change of Address requirements](https://support.google.com/webmasters/answer/9370220) describe those steps. A `site:sqafe.com` search can be a rough spot check, but [its results are not exhaustive](https://developers.google.com/search/docs/monitor-debug/search-operators/all-search-site); it cannot establish that the site is absent from the index.

## Owner actions in Bing and external properties

- [ ] Finish Bing Webmaster Tools verification if it is still pending. The site hosts the existing `BingSiteAuth.xml` challenge file. Confirm the account accepts that file, submit the canonical sitemap, then inspect the same six URLs. If Bing offers a site move for the verified old and new properties, follow its current requirements.
- [ ] Audit owner-controlled profiles and external integrations for `safescan-qr.onrender.com`: social profiles, shared documents, QR codes printed or distributed for demos, OAuth authorized origins and redirect URIs, webhook callbacks, and mobile client configuration. The GitHub repository website field and README already use `https://sqafe.com`. Update other public links where appropriate. Change integration destinations only after checking the associated provider settings and client behavior; existing Render-host service routes remain active.
- [ ] Record changes and actual search visibility observations in [the brand search log](brand-serp-log.md). Date each observation, identify the search engine and property, and keep Search Console/Bing measurements separate from manual searches. Avoid a promised indexation or ranking date.

The broader [search visibility checklist](offpage.md) covers accurate brand references and measurement. Google treats a permanent redirect as a [strong canonical signal](https://developers.google.com/search/docs/crawling-indexing/301-redirects), but neither redirects nor sitemap submission guarantee that a page will appear in search results. Keep the redirects in place while engines process the move.

## Repeatable deployment check

Run `python3 scripts/seo_smoke.py` after deployment and review its dated Markdown output. It checks the live public redirect samples, robots and sitemap, and the metadata and internal reachability of the sitemap pages. The [2026-11-17 baseline](crawl-report-2026-11-17.md) passed those checks. The script does not access Search Console or Bing and cannot report indexed-page counts or rankings.

If checking by hand, use `GET` for the final canonical page. Some canonical routes are GET-only, so following a `HEAD` request with `curl -sIL` can end in `405` after a correct `301`:

```bash
curl -sS -o /dev/null -D - 'https://safescan-qr.onrender.com/plans?x=1'
curl -sSL -o /dev/null -w '%{http_code} %{num_redirects} %{url_effective}\n' 'https://safescan-qr.onrender.com/learn'
curl -sS 'https://sqafe.com/robots.txt'
curl -sS 'https://sqafe.com/sitemap.xml'
```

The reviewed sitemap omits `<lastmod>`. Add it only when the application can supply accurate dates for significant content changes, as [Google recommends](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap).
