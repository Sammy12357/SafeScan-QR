# Sqafe search visibility: owner checklist

**Reviewed:** 2026-11-17. **Owner:** Sam / Sqafe. **Canonical site:** <https://sqafe.com/>. This is an execution checklist, not a ranking forecast. Owner screenshots show three indexed URLs, but no complete Search Console or Bing Webmaster Tools report was available, so search traffic, rankings, and indexed-page counts are **not yet measured**. The reviewed sitemap includes `/`, `/about`, `/learn`, `/learn/after-scanning-suspicious-qr`, `/learn/parking-meter-qr-scams`, and `/contact` after the brand release; check its live contents before every submission.

**Current state:** The owner confirmed the `sqafe.com` Domain property is verified. On 2026-11-15, Search Console showed “Sitemap submitted successfully” for `https://sqafe.com/sitemap.xml`. Its Performance and Indexing reports were still processing then. Owner-provided URL Inspection screenshots on 2026-11-17 show the homepage, `/about`, and `/learn` as indexed. Recheck the sitemap status and remaining URLs after Google processes the property.

For the current legacy-host redirect evidence and the indexing-specific Search Console handoff, use [the indexing checklist](indexing-checklist.md).

## Verify ownership and submit the sitemap

- [x] **Google Search Console:** Add and verify the **Domain property** `sqafe.com` through Cloudflare DNS. Keep the verification record in place. Google says a Domain property covers protocol and subdomain variations and requires DNS verification. [Property setup](https://support.google.com/webmasters/answer/34592), [ownership verification](https://support.google.com/webmasters/answer/9008080).
- [x] Submit `https://sqafe.com/sitemap.xml` under **Sitemaps** in the verified property. Search Console accepted the submission on 2026-11-15. Sitemap submission helps discovery but does **not** guarantee crawling or indexing. [Google sitemap guidance](https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap).
- [ ] After Google has processed the property and this release is live, inspect the homepage, `/about`, `/learn`, both guide URLs, and `/contact` with **URL Inspection**. Record any discovery, crawl, canonical, or indexing issue.
- [ ] **Bing Webmaster Tools:** Add `https://sqafe.com/` manually and choose **XML File** verification. The downloaded file is now hosted at `https://sqafe.com/BingSiteAuth.xml`; click **Verify** in Bing. Submit `https://sqafe.com/sitemap.xml` in **Sitemaps** and inspect the same six URLs after this release. Keep the XML file hosted so Bing can recheck ownership. [Add and verify](https://www.bing.com/webmasters/help/add-and-verify-site-12184f8b), [sitemaps](https://www.bing.com/webmasters/help/Sitemaps-3b5cf6ed).
- [ ] Record who controls each property and DNS record, the verification date, and any access handoff in the owner's private records. Do not paste login credentials or other private codes into a public issue. The downloaded Bing XML challenge is intentionally public and must remain unchanged for its file-based verification method.

## Build accurate brand references

- [ ] Confirm that the existing [SafeScan QR GitHub repository](https://github.com/Sammy12357/SafeScan-QR) and any owner-controlled profiles use the public brand **Sqafe**, the domain `https://sqafe.com`, and a truthful description of the current scanner. Explain the relation to the product name **SafeScan QR** where needed.
- [ ] Consider a launch or software directory listing only when the product meets that site's current eligibility rules and someone can maintain the listing. Include one working canonical URL, current screenshots, and accurate availability. Record the profile URL and owner. Do not create duplicate or placeholder listings, invent reviews, or list a mailing address that the business has not verified.
- [ ] Seek genuine references through useful, original QR safety guidance, direct partnerships, or interviews where the other site chooses to cite the work. Do not buy ranking links, trade links at scale, use automated link placement, or submit to low-quality directories; these are examples of [Google link spam](https://developers.google.com/search/docs/essentials/spam-policies#link-spam).
- [ ] Add a profile to future `sameAs` structured data only after the owner confirms it is authentic, public, and controlled by Sqafe. A new profile or backlink is **not** an indexation or ranking guarantee.

## Reddit: human participation only

- [ ] Before commenting or posting, read the specific community's current rules. Participate where you can answer a real QR safety question with useful information. State your affiliation with Sqafe when relevant. Link to a Sqafe guide only if the link helps answer the question and that community allows it; a useful answer can stand without a link.
- [ ] Avoid repeated promotional posts, copy-pasted replies, unsolicited messages, bots, and automated account creation. Reddit's [spam policy](https://support.reddithelp.com/hc/en-us/articles/360043504051-Spam) asks business owners to be thoughtful about the frequency of their links and to follow community rules. This repository does not post to Reddit or create accounts.
- [ ] Keep an internal note of any **actual** contribution: date, community, topic, URL, affiliation disclosure, and outcome. Do not treat a removed post or an unclicked link as a backlink win.

## Measure what happens

Once verification is complete, take a baseline and compare the same date range each month. Label the source, property, country/device filters, and search type. Google and Bing count impressions and positions differently, so keep their reports separate. Search Console's [Performance report](https://support.google.com/webmasters/answer/7576553) shows clicks, impressions, CTR, and average position; Bing's [Search Performance report](https://www.bing.com/webmasters/help/search-performance-c680da36) also shows crawl and indexed-page data. Prefer trends in impressions and clicks over a single position number, as [Google advises](https://support.google.com/webmasters/answer/17010961).

| Measure | Source and scope | Baseline | Monthly update |
| --- | --- | --- | --- |
| Search clicks, impressions, CTR | GSC **Search results / Web**, site and each indexable URL | Not collected | Record actual values and dates |
| Queries and average position | GSC, selected primary terms from [keyword map](keyword-map.md) | Not collected | Record actual query/page pairs; position is an average |
| Search clicks, impressions, CTR, position | Bing Search Performance; record the selected traffic source, site, and URLs | Not collected | Record separately from Google |
| Sitemap processing and indexing | GSC Sitemaps / Pages; Bing Sitemaps / Indexed pages | Not collected | Record errors and confirmed indexed URLs; submission is not indexation |
| Core Web Vitals | GSC mobile and desktop URL groups | Not collected | Record Good / Need improvement / Poor when field data exists |
| Earned brand references | Owner's list of real profile or article URLs | Not collected | Record source URL and date; no estimated link counts |

The [Core Web Vitals report](https://support.google.com/webmasters/answer/9205520) may show **No data available** for a new or low-traffic property; record that state as unavailable, not zero or a pass. There is no credible basis here for a “top of search” date, a target rank, or fabricated keyword volume.

## Repeatable public-page check

Run `python3 scripts/seo_smoke.py` after a deployment. It checks sample legacy, `www`, and HTTP redirects without following them; reads the live robots file and sitemap; visits sitemap URLs on `sqafe.com`; and checks page metadata and whether each sitemap URL is reachable from home within three links through other sitemap pages. It prints a dated Markdown report. To keep a reviewed snapshot, run `python3 scripts/seo_smoke.py --output docs/seo/crawl-report-YYYY-MM-DD.md` and inspect the generated file before committing it. This read-only check does not query Google/Bing rankings and cannot establish that a page is indexed. The [2026-11-17 baseline](crawl-report-2026-11-17.md) records the responses before this handoff.
