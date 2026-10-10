# Zero-yield legitimate source retry and lockbox readiness

- Decision: **BLOCKED_NO_CERTIFIED_LOCKBOX_DATA**
- Retry run: `2026-10-09T10:14:00+00:00`; 15 previously zero-yield sources retried.
- Retained URLs: 0; unique normalized URLs: 0; registered domains: 0.
- Legitimate class counts: `{}`.
- Cohort counts: `{}`.
- Required URL cohorts: `["homepage", "path", "search", "query", "multiple_parameters", "encoded", "fragment", "pagination", "tracking", "documentation", "login_account", "long_url"]`.
- Missing URL cohorts: `["homepage", "path", "search", "query", "multiple_parameters", "encoded", "fragment", "pagination", "tracking", "documentation", "login_account", "long_url"]` (NO_COHORTS_OBSERVED).
- Historical domain union: 349480; domain overlaps: `{}`.
- Retried-source domain overlap checks: `{}`.
- Legacy phishing-feed domains: 323590; overlap with historical datasets: 9606.
- Provenance errors: 0; normalized duplicates remaining: 0.
- Training: **not started**.
- Two-class lockbox independence: **NOT_PROVEN**.

## Source retry outcomes

| Source | Registered domain | HTTP status | Rows | Result |
|---|---|---:|---:|---|
| Smithsonian | si.edu | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| NOAA | noaa.gov | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| U.S. Congress | congress.gov | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| U.S. Department of State | state.gov | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| U.S. Department of Education | ed.gov | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| Princeton University | princeton.edu | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| University of Toronto | utoronto.ca | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| Reuters | reuters.com | 401 | 0 | homepage: HTTPError: HTTP Error 401: HTTP Forbidden |
| International Monetary Fund | imf.org | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| OECD | oecd.org | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| Encyclopaedia Britannica | britannica.com | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| Wayfair | wayfair.com | 429 | 0 | homepage: HTTPError: HTTP Error 429: Too Many Requests |
| Government of Ireland | gov.ie | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| Parliament of the United Kingdom | parliament.uk | 403 | 0 | homepage: HTTPError: HTTP Error 403: Forbidden |
| Australian Government | australia.gov.au | blocked/unknown | 0 | homepage: URLError: <urlopen error redirect outside approved HTTPS registered domain blocked> |

## Assessment

No fresh, independently sourced phishing lockbox rows were reserved. Prior phishing-feed entries are historical and feed membership alone does not establish current maliciousness.
Every candidate source domain was screened against scanned historical URL CSV datasets, the fixed benchmark URL list, and the legacy phishing feed. Source collection retained only observed HTTPS URLs with individual 2xx responses and same-registered-domain final URLs.

Machine-readable details: [zero_yield_retry_readiness.json](./zero_yield_retry_readiness.json).
