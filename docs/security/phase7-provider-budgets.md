# Phase 7 outbound provider budgets

`PROVIDER_BUDGETS_ENABLED` is **off by default**. This draft does not change
live provider use until the owner deliberately enables it. With the guard on,
every outbound source needs a positive monthly call cap:

| Source | Monthly environment setting | Maximum in-flight calls per worker |
| --- | --- | ---: |
| Google Web Risk | `WEB_RISK_MONTHLY_BUDGET` | 2 |
| Legacy Safe Browsing (noncommercial opt-in only) | `SAFE_BROWSING_MONTHLY_BUDGET` | 2 |
| PhishTank feed refresh | `PHISHTANK_FEED_MONTHLY_BUDGET` | 1 |
| RDAP | `RDAP_MONTHLY_BUDGET` | 2 |
| WhoisXML | `WHOISXML_MONTHLY_BUDGET` | 2 |
| SecurityTrails | `SECURITYTRAILS_MONTHLY_BUDGET` | 2 |
| Wayback | `WAYBACK_MONTHLY_BUDGET` | 2 |

An absent, malformed, or zero cap denies that source before any network call.
Google denial returns an unverified reputation signal; it cannot satisfy the
required verification coverage for a SAFE verdict. PhishTank remains a local
snapshot lookup on every scan. Its budget counts only feed downloads; if a
refresh is denied, the last snapshot remains usable until its normal two-hour
freshness limit, then PhishTank becomes unverified. Optional domain-age
sources fall through to another bounded source. Temporary unavailable domain
age results are not cached for the normal domain-age TTL.

The SQLite `provider_budget_usage` table counts attempts and failures by a
fixed provider name and UTC month, retaining about two years. Three
consecutive errors open a 60-second circuit; a successful retry closes it.
Provider keys, URLs, QR payloads, account IDs, and IPs are not stored in this
table. Owners can inspect counts, caps, errors, and circuit status in Admin →
Settings. Direct `python-whois` socket lookup is skipped while this guard is
enabled because its library call has no dependable hard timeout; RDAP and
other configured HTTP sources remain available.

## Release gates

1. Choose each cap from the actual provider agreement and expected usage.
   Set caps for every source that should run, then enable the guard. This
   document deliberately does not guess provider allowance or price.
2. Keep one Render worker and one instance until a shared concurrency gate is
   added. The SQLite counter is shared across workers, but the in-flight
   semaphores are per process.
3. Confirm the production database is on the persistent disk and writable.
   If counter storage fails, outbound calls are denied. Check Admin Settings
   after a deployment and verify the attempts rise only on actual requests.
4. Test with a deliberately exhausted Web Risk cap and confirm scans show
   incomplete verification rather than SAFE. Confirm a stale PhishTank feed is
   also unverified. Verify the existing Phase 2 and Phase 3 release gates
   before any production merge.
