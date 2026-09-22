# Cyber Risk KRIs — Handoff

_Last updated: 2026-09-22_

A working reference for picking this project back up. Covers what the project does,
how it's built, the decisions and gotchas behind it, and where to go next.

---

## 1. What this project is

Collects public cyber-security data and turns it into **key risk indicators (KRIs)**
for a cyber-security advisor. Three sources:

| Source | What | Endpoint |
|---|---|---|
| **NIST NVD** | Full CVE catalog (severity, CWE, products) | `services.nvd.nist.gov/rest/json/cves/2.0` |
| **CISA KEV** | CVEs *confirmed exploited in the wild* (~1,700) | public JSON feed |
| **SEC EDGAR** | 8-K **Item 1.05** material cyber-incident disclosures | `efts.sec.gov/LATEST/search-index` |

The headline analysis joins KEV to NVD ("enrichment") and produces two HTML reports
plus a landing page, all FINRA-branded.

- **GitHub**: https://github.com/larson-jon/cyber_risk_kris (branch `main`)
- **Latest commit at handoff**: `1de532a`

---

## 2. Repo layout

```
collectors/            # data collection (the CLI lives here)
  cli.py               # entry point: python -m collectors.cli <cmd>
  config.py            # .env config (NVD_API_KEY / NIST_API_KEY, DATA_DIR, EDGAR_USER_AGENT)
  http_client.py       # shared requests session (retries) + sliding-window RateLimiter
  nvd.py               # NVD 2.0 client (pagination, windowed backfill, get_cve by ID)
  kev.py               # CISA KEV catalog client
  edgar.py             # EDGAR full-text search + primary-doc resolution + narrative extraction
  flatten.py           # flatten NVD/KEV/EDGAR to CSV rows; KEV+NVD join; SIC + theme tagging
analysis/              # report generators (read data/, write HTML)
  finra_brand.py       # SHARED brand module: palette, fonts, base_css(), brand_header(), info()
  eda_kev.py           # KEV x NVD report -> data/kev_eda.html
  edgar_dashboard.py   # 8-K dashboard -> data/edgar_dashboard.html
  nvd_monthly_totals.py# fetch/cache total CVEs published per month -> data/nvd_monthly_totals.json
  readme_html.py       # render README.md -> reports/readme.html (dependency-free markdown)
reports/               # COMMITTED HTML snapshots (data/ is gitignored, reports/ is not)
  index.html           # landing page linking the reports + docs
  kev_eda.html, edgar_dashboard.html, readme.html
  finra logo.png       # official FINRA ERM logo (used in headers)
data/                  # gitignored EXCEPT data/nvd_monthly_totals.json
README.md, HANDOFF.md, requirements.txt, .env.example, .gitignore
```

Dependencies: `requests`, `python-dotenv` (see `requirements.txt`). Python 3.13 on Windows/PowerShell.

---

## 3. How to run things

```powershell
pip install -r requirements.txt
Copy-Item .env.example .env      # then add the NVD API key (see secrets note below)

# Collect
python -m collectors.cli kev                     # CISA KEV catalog
python -m collectors.cli nvd --last-days 7        # NVD incremental
python -m collectors.cli enrich                   # KEV + NVD joined (the key dataset) -> ~20 min
python -m collectors.cli edgar --item 1.05        # SEC 8-K material cyber incidents

# Reports (read newest data/, write HTML)
python analysis/eda_kev.py
python analysis/edgar_dashboard.py data/edgar_8k_item105_<ts>.csv
python analysis/nvd_monthly_totals.py 2025 2026   # (re)build the totals cache
python analysis/readme_html.py

# Publish report snapshots (data/ is gitignored, so copy into reports/)
Copy-Item data/kev_eda.html reports/kev_eda.html -Force
Copy-Item data/edgar_dashboard.html reports/edgar_dashboard.html -Force
```

Every collector command takes `--format csv|json|both` (default `csv`). Output is
timestamped into `data/`.

---

## 4. Key design decisions (and why)

- **Enrichment pulls KEV CVEs by ID, not the whole NVD catalog.** ~1,700 targeted
  lookups vs. paging ~374k records. KEV spans CVEs of any age (2002–present) and
  by-ID lookup gets each one regardless of publish date. This is the right call for
  KEV-centric KRIs. See `run_enrich` in `cli.py`.
- **EDGAR filters on the structured `items` field, not phrase matching.** The
  full-text hit's `_source.items` reliably says whether a filing is truly 1.05.
- **EDGAR resolves each filing's *primary* 8-K document** (via the filing index /
  `-index-headers.html`) before extracting the narrative. The raw search hit often
  points to an *exhibit*, which caused empty descriptions and false positives early on.
  `edgar.py: primary_document_url()`.
- **Reports are static HTML with inline Chart.js from CDN** — no build step, open
  directly or serve via GitHub Pages.
- **`analysis/finra_brand.py` is the single source of truth for styling.** Change
  brand once, regenerate, all reports update.
- **Tooltips use the native `title` attribute**, not CSS popovers — CSS ones got
  clipped inside the scrollable/sticky tables.

---

## 5. Gotchas / things that bit us

- **NVD date params need care.** Any date range is capped at **120 days** (backfills
  auto-chunk). Datetime must be millisecond ISO. A wide `lastModified` window can
  return almost the entire dataset because NVD does bulk re-scoring passes — use
  `pubStartDate`/`pubEndDate` for "published in year X", `lastMod*` for incremental sync.
- **NVD API key is a 10x rate boost** (5→50 req/30s). Enrichment is ~20 min with a
  key, far slower without. Config accepts `NVD_API_KEY` **or** `NIST_API_KEY`.
- **EDGAR fetches occasionally time out** (SEC 503/read timeouts). The shared session
  retries, but the 8.01 verification count varied run-to-run because timed-out
  candidates get dropped. Item 1.05 is small and stable; **8.01 is noisy** (see below).
- **PowerShell mangles inline `python -c` with quotes/`<`/`>`.** Write a temp `.py`
  file for any non-trivial check instead of inlining.
- **`git push` prints to stderr**, so PowerShell shows a red "error" even on success.
  Confirm with the `<sha>..<sha> main -> main` line and `git status -sb`.

---

## 6. Data caveats to remember (important for interpretation)

- **"exploited CVEs" in the KEV report are KEV-only** — a tiny fraction of all
  published CVEs. The secondary-axis line shows the true monthly totals for context
  (e.g. Aug 2026: ~12,700 published vs ~31 added to KEV). Do not read the bars as
  total CVE volume.
- **Time-to-exploitation "age"** = KEV `date_added` − NVD `published`. Negative values
  are real (exploited before NVD publication = strong zero-day signal). Use the
  **median**, not the mean — the mean is skewed by old CVEs newly exploited.
- **EDGAR incident tags** (incident_type, third_party, data_types, status) are
  **keyword-derived from filing text** — a first-pass classification, not ground truth.
  An LLM pass would improve them (see next steps).
- **8-K filings rarely quantify breach cost in dollars.** Dollar figures, when they
  exist, surface later in 10-Q/10-K, not the 8-K.

---

## 7. Current data snapshot (as of 2026-09-22)

- KEV enriched: **1,717** records, all matched to NVD (0 missing).
- 2025: 245 new KEV entries, median time-to-exploit 26 days.
- 2026 YTD: 233 new KEV entries, median 15 days. ~93 zero-day (age <=0) records across both years.
- Total CVEs published: **49,972 (2025)**, **71,012 (2026 YTD)**.
- EDGAR Item 1.05: **23** material cyber-incident filings in 2026 (finance & medical-device heavy; ~half third-party/vendor).

---

## 8. Open items / next steps

Roughly in priority order:

1. **EDGAR 8.01 collector is built but not in the reports.** `edgar --item 8.01`/`both`
   works, but verification is slow and the count is non-deterministic under SEC
   timeouts. To use it: add a retry-until-fetched pass so genuine filings aren't
   dropped on transient errors, then decide whether to surface 8.01 in the dashboard.
   (Reports were deliberately set to 1.05-only.)
2. **Exploitation-rate KRI** — exploited / total published per month, as a %. The data
   is already cached (`nvd_monthly_totals.json`); just needs a derived series + display.
3. **LLM-based narrative tagging** for EDGAR incident_type/data/status (replace/augment
   the keyword rules in `flatten.py: _tag_narrative`).
4. **Dollar-impact enrichment** — link each 8-K company to its later 10-Q/10-K and
   extract quantified cyber costs (the numbers live there, not in the 8-K).
5. **Automate refresh** — a scheduled job (or Kiro hook) to re-pull, regenerate, and
   copy snapshots into `reports/`.
6. **GitHub Pages** — enable Pages on `/reports` to publish the dashboards as a URL.

---

## 9. Security / housekeeping notes

- **`.env` holds the NVD API key and is gitignored.** The key was visible in a
  terminal session during development — **rotate it** at nvd.nist.gov when convenient.
- `data/` is gitignored except `data/nvd_monthly_totals.json` (small report reference
  data, intentionally tracked via a `.gitignore` negation).
- The FINRA logo in headers is the **Enterprise Risk Management** department logo,
  placed on a white band (black logo stays legible/unaltered per brand rules). Swap
  for the primary corporate logo if these go beyond ERM use.
- Report snapshots in `reports/` are **static** — regenerate and re-copy after new
  data pulls; they don't auto-update.
