# Cyber KRIs — Security Data Collectors

Pulls cyber security data from public sources into local JSON files. Currently supported:

- **NIST NVD** — CVE records via the [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
- **CISA KEV** — the [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **SEC EDGAR** — 8-K **Item 1.05** material cybersecurity-incident disclosures via [EDGAR full-text search](https://efts.sec.gov/LATEST/search-index)

The design leaves room to add more sources later (each lives in its own module under `collectors/`).

## Project layout

```
collectors/
  __init__.py
  config.py        # env/.env configuration (API key, data dir)
  http_client.py   # shared requests session (retries) + sliding-window rate limiter
  nvd.py           # NIST NVD API 2.0 client (pagination, incremental pulls)
  kev.py           # CISA KEV catalog client
  flatten.py       # flatten NVD/KEV/EDGAR records into CSV rows; join KEV+NVD
  edgar.py         # SEC EDGAR 8-K Item 1.05 (material cyber incident) client
  cli.py           # command-line entry point
.env.example       # copy to .env and fill in
requirements.txt
```

## Setup

```powershell
# From the project root
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Configure (optional but recommended for NVD)
Copy-Item .env.example .env
# then edit .env and paste your NVD API key
```

Get a free NVD API key at <https://nvd.nist.gov/developers/request-an-api-key>. Without one you're limited to 5 requests / 30s; with one, 50 / 30s.

## Usage

Run collectors as a module:

```powershell
# Full CISA KEV catalog
python -m collectors.cli kev

# CVEs modified in the last 7 days (incremental pull)
python -m collectors.cli nvd --last-days 7

# CVEs modified in an explicit range (auto-chunked into <=120-day windows)
python -m collectors.cli nvd --start 2024-01-01 --end 2024-06-01

# All CVEs *published* in a range, with severity (full population, not just exploited)
python -m collectors.cli nvd --pub-start 2025-01-01 --pub-end 2025-12-31

# Both sources at once
python -m collectors.cli all --last-days 7

# KEV enriched with NVD detail (severity, CWEs, affected products), joined on cve_id
python -m collectors.cli enrich

# SEC 8-K Item 1.05 material cyber-incident filings (default: since 2026-01-01)
python -m collectors.cli edgar
python -m collectors.cli edgar --start 2026-01-01 --end 2026-06-30

# Verbose logging
python -m collectors.cli -v kev
```

### Output format

Every command accepts `--format` with `csv` (default), `json`, or `both`:

```powershell
python -m collectors.cli kev                      # CSV (default)
python -m collectors.cli nvd --last-days 7 --format json
python -m collectors.cli all --last-days 7 --format both
```

Output is written to the `data/` directory (configurable via `DATA_DIR`) as timestamped files, e.g. `data/cisa_kev_20260922T130000Z.csv`. CSVs are UTF-8 with a BOM so they open cleanly in Excel.

**CSV columns**

- **KEV**: `cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, cwes, notes`
- **NVD**: `cve_id, source_identifier, published, last_modified, vuln_status, description, cvss_version, cvss_base_score, cvss_base_severity, cvss_vector, cvss_source, cwes, reference_urls`

For NVD, the CVSS columns come from the best available metric, preferring v4.0, then v3.1, v3.0, and finally v2. Multi-value fields (CWEs, reference URLs) are joined with `; ` in a single cell. Use `--format both` if you also want the full nested JSON for fields the CSV doesn't flatten.

## Enrichment: KEV + NVD

`enrich` builds the combined dataset most useful for KEV-based KRIs. It fetches the full CISA KEV catalog, then looks up each KEV CVE in NVD **by ID** (`cveId` param) and joins the two on `cve_id` — one row per KEV entry:

```powershell
python -m collectors.cli enrich              # CSV (default)
python -m collectors.cli enrich --format both
```

This is far cheaper than downloading all of NVD: it makes ~1,700 targeted lookups (one per KEV CVE) instead of paging the entire ~374k-record catalog. KEV references CVEs of any age (the catalog spans 2002–present), and by-ID lookup retrieves each one regardless of publish date. Output: `data/kev_enriched_<timestamp>.csv`.

**Enriched CSV columns**

KEV context first, then NVD detail (prefixed `nvd_` to avoid clashing with KEV's own fields):

`cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_campaign_use, kev_cwes, short_description, in_nvd, nvd_published, nvd_last_modified, nvd_vuln_status, cvss_version, cvss_base_score, cvss_base_severity, cvss_vector, cvss_source, nvd_cwes, nvd_affected_products, nvd_description`

`in_nvd` is `False` for the rare KEV CVE with no NVD record yet; its `nvd_*` columns are then blank. `nvd_affected_products` is a de-duplicated `vendor:product` list parsed from NVD CPE data (capped at 25 entries per row).

> **Rate limits & runtime**: enrichment issues one request per KEV CVE, so an NVD API key matters here. With a key (~50/30s) the full run takes roughly 20 minutes; without one (5/30s) it is about 10x slower.

## SEC EDGAR: 8-K cyber-incident filings (Item 1.05 & 8.01)

`edgar` collects Form 8-K cyber disclosures and extracts each filing's incident narrative. It queries the official EDGAR full-text search API and supports two disclosure paths via `--item`:

- **`1.05`** (default) — *material* cybersecurity incidents (SEC rule effective Dec 2023). Every 1.05 filing is cyber-related, so we keep filings whose structured `items` contain `1.05`.
- **`8.01`** — *voluntary / non-material* cyber events filed under "Other Events". Because 8.01 is a catch-all, we search for cyber language, then **verify** each candidate by fetching its primary 8-K document and confirming the 8.01 section is genuinely about a cyber incident. This drops the many false positives where a cyber phrase only appears in an attached exhibit.
- **`both`** — collect 1.05 and 8.01 together (8.01 excludes any filing also carrying 1.05, to avoid double-counting).

```powershell
python -m collectors.cli edgar                                   # Item 1.05, since 2026-01-01
python -m collectors.cli edgar --item 8.01                       # voluntary cyber disclosures
python -m collectors.cli edgar --item both --format both         # everything, CSV + JSON
python -m collectors.cli edgar --item 1.05 --no-descriptions     # skip narrative fetch (1.05 only)
```

The default search window starts **2026-01-01** for both items; pass `--start` to go earlier (coverage allows back to Dec 2023).

**EDGAR CSV columns**

`disclosure_type, accession, company, ticker, cik, form, filing_date, period_ending, items, business_location, incident_description, filing_url`

- `disclosure_type` is `1.05` or `8.01`.
- `incident_description` is a plain-text excerpt of the relevant item's narrative, pulled from the **primary** 8-K document (not exhibits) and trimmed to ~2000 characters. Use `--no-descriptions` (1.05 only) to skip fetching filing bodies for a faster metadata-only run. For 8.01, descriptions are always fetched because they are required for the cyber-verification step.
- Rows are sorted newest-first. `form` distinguishes original `8-K` from `8-K/A` amendments. `items` lists all item numbers on the filing (e.g. `1.05; 9.01`).

> **Accuracy note**: raw full-text search for cyber terms is very noisy for 8.01 — most candidates are unrelated filings (contracts, results) that merely mention a cyber word in an exhibit. Verification reads each filing's **primary 8-K document**, extracts the Item 8.01 narrative, and keeps the filing only if cyber language appears **in that narrative**. This drops the large majority of candidates as false positives while keeping genuine disclosures. One residual limitation: some companies bundle several unrelated events under a single Item 8.01 (e.g. a note redemption *and* a cyber note), so an occasional non-cyber-primary filing can still be kept. Always read `incident_description` / `filing_url` before relying on a specific 8.01 row.

> **SEC fair access**: EDGAR requires a descriptive `User-Agent` identifying the requester and limits clients to 10 requests/second. Set `EDGAR_USER_AGENT` in `.env` (e.g. `"Acme Corp research jane.doe@acme.com"`) or pass `--user-agent`. The client rate-limits itself and works without one, but setting it is the polite/expected practice.

## Notes on the APIs

**NVD API 2.0**
- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Offset pagination via `startIndex` / `resultsPerPage` (max 2000 per page) — handled automatically.
- Incremental pulls use `lastModStartDate` / `lastModEndDate`; any date range is capped at 120 days, so larger backfills are chunked automatically.
- API key is sent in the `apiKey` header. A sliding-window rate limiter keeps requests just under the published limits.

**CISA KEV**
- Single public JSON feed, no key required: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- The saved file includes catalog metadata (`catalogVersion`, `dateReleased`, `count`) plus the `vulnerabilities` list.

## Reports

Analysis scripts in `analysis/` generate self-contained HTML reports:

- `analysis/eda_kev.py` &rarr; KEV &times; NVD exploratory analysis (trends, time-to-exploitation stats, filterable tables).
- `analysis/edgar_dashboard.py` &rarr; SEC 8-K cyber-incident dashboard (incident types, industry, third-party share, narratives).

By default these write into `data/` (gitignored). Shareable snapshots are kept in `reports/`, with `reports/index.html` as a landing page linking both. To refresh the committed snapshots after new data pulls, regenerate the reports and copy the HTML into `reports/`.

`analysis/readme_html.py` renders this README as a FINRA-branded `reports/readme.html`, linked from the landing page. Re-run it after editing the README to refresh the HTML docs.

`analysis/nvd_monthly_totals.py` fetches per-month published-CVE counts — both the **total** and the **High/Critical** subset (the denominators the KEV-only data can't provide) — and caches them to `data/nvd_monthly_totals.json` as `{"2025-01": {"total": N, "highCritical": M}, ...}`. The KEV report plots both as secondary-axis lines so exploited counts can be read against published volume — e.g. a month with ~12,700 CVEs published (~800 High/Critical) vs. ~30 added to KEV. Run `python analysis/nvd_monthly_totals.py 2025 2026` to (re)build the cache.

## Extending

To add a new source, create `collectors/<source>.py` with a small client class that reuses `build_session()` from `http_client.py`, then wire a subcommand into `cli.py`.
