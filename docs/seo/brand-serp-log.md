# Sqafe branded search log

Use this log for observations, not rank promises. Record date, location, language, device, search engine, exact query, screenshot or report source, Sqafe URL shown, and whether spelling correction appeared. Google Search Console's query impressions and average position should be logged separately from a manual results page; they measure different things.

| Date and vantage | Source and query | Observed result | Limits |
| --- | --- | --- | --- |
| 2026-11-15, Toronto, English, browser | Google `sqafe` | Search challenge prevented inspection. | No Google rank or indexation conclusion. |
| 2026-11-15, Toronto, English, browser | Bing `sqafe` | Bing offered results for “safe” and asked whether to show only `sqafe`. Sqafe was absent from the first visible group. | The rewrite and search challenge prevent a reliable rank or indexation conclusion. |

## Repeatable check

1. In Search Console, open **Performance → Search results**, set **Web**, and filter query **exactly** `sqafe`. Record date range, country, device, impressions, clicks, and average position. “No data” is different from zero. Also compare relevant variants if data appears.
2. In **URL Inspection**, inspect the homepage and `/about`, then record reported crawl/index status and Google's selected canonical URL. A sitemap submission or indexing request is not proof of indexing.
3. For a manual search, use the same country, language, device, and signed-out browser each time. Note any correction or search challenge. Do not send incentivized traffic or ask users to search and click for ranking purposes.

[Google's site-name guidance](https://developers.google.com/search/docs/appearance/site-names) explains that the displayed name is automated; [Search Console performance data](https://support.google.com/webmasters/answer/7576553) is the source for actual query trends.
