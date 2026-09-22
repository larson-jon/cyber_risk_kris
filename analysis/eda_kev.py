"""Exploratory analysis of the KEV-enriched dataset for 2025 and 2026.

Computes, per month for each year:
- new KEV entries (by CISA ``date_added``)
- newly published CVEs among KEV entries (by NVD ``nvd_published``)
- average and median age between publication (first captured in NVD) and
  exploitation (added to KEV), in days

Also emits a per-entry detail table (with KEV + NVD descriptions). Writes a
self-contained HTML report to data/kev_eda.html.
"""

from __future__ import annotations

import csv
import glob
import html
import json
import statistics
import sys
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import finra_brand as fb  # noqa: E402

DATA_DIR = Path("data")
YEARS = [2025, 2026]
MONTH_LABELS = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]


def _latest_enriched() -> Path:
    files = sorted(glob.glob(str(DATA_DIR / "kev_enriched_*.csv")))
    if not files:
        raise SystemExit(
            "No kev_enriched_*.csv found in data/. Run: python -m collectors.cli enrich"
        )
    return Path(files[-1])


def _parse_date(value: str) -> date | None:
    if not value:
        return None
    value = value.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def load_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _truncate(text: str, limit: int = 240) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "..."


def compute_year(rows: list[dict], year: int) -> dict:
    new_kev = defaultdict(int)
    new_cve = defaultdict(int)
    ages_by_month = defaultdict(list)
    ransomware = defaultdict(int)
    entries: list[dict] = []

    for r in rows:
        added = _parse_date(r.get("date_added", ""))
        published = _parse_date(r.get("nvd_published", ""))

        if published and published.year == year:
            new_cve[published.month] += 1

        if added and added.year == year:
            m = added.month
            new_kev[m] += 1
            if r.get("known_ransomware_campaign_use", "").strip().lower() == "known":
                ransomware[m] += 1
            age = (added - published).days if published else None
            if age is not None:
                ages_by_month[m].append(age)
            entries.append(
                {
                    "cve_id": r.get("cve_id", ""),
                    "date_added": r.get("date_added", ""),
                    "nvd_published": (r.get("nvd_published", "") or "")[:10],
                    "age_days": age,
                    "severity": r.get("cvss_base_severity", "") or "UNKNOWN",
                    "score": r.get("cvss_base_score", ""),
                    "ransomware": r.get("known_ransomware_campaign_use", ""),
                    "vendor": r.get("vendor_project", ""),
                    "product": r.get("product", ""),
                    "name": r.get("vulnerability_name", ""),
                    "kev_desc": r.get("short_description", ""),
                    "nvd_desc": r.get("nvd_description", ""),
                }
            )

    monthly = []
    for i, label in enumerate(MONTH_LABELS, start=1):
        ages = ages_by_month.get(i, [])
        monthly.append(
            {
                "label": label,
                "month": i,
                "new_kev": new_kev.get(i, 0),
                "new_cve": new_cve.get(i, 0),
                "ransomware": ransomware.get(i, 0),
                "min_age_days": min(ages) if ages else None,
                "max_age_days": max(ages) if ages else None,
                "avg_age_days": round(statistics.mean(ages), 1) if ages else None,
                "median_age_days": round(statistics.median(ages), 1) if ages else None,
                "age_sample": len(ages),
                # Records exploited on/before NVD publication (age <= 0):
                # effectively zero-day or near-zero-day exploitation.
                "zero_day_count": sum(1 for a in ages if a <= 0),
            }
        )

    entries.sort(key=lambda e: e["date_added"], reverse=True)
    all_ages = [e["age_days"] for e in entries if e["age_days"] is not None]
    return {
        "year": year,
        "monthly": monthly,
        "entries": entries,
        "total_kev": sum(new_kev.values()),
        "total_new_cve": sum(new_cve.values()),
        "total_ransomware": sum(ransomware.values()),
        "median_age": round(statistics.median(all_ages), 1) if all_ages else 0,
        "mean_age": round(statistics.mean(all_ages), 1) if all_ages else 0,
    }


def _active(monthly: list[dict]) -> list[dict]:
    active = [m for m in monthly if m["new_kev"] or m["new_cve"]]
    return active or monthly


def build_age_stats_series(results: list[dict]) -> list[dict]:
    """Flatten all months across years into one chronological series.

    Each item has year, month label, and min/max/mean/median age (days) plus
    the sample size. Months with no aged entries are included but marked empty.
    """
    series: list[dict] = []
    for res in results:
        for m in res["monthly"]:
            if m["age_sample"] == 0:
                continue  # skip months with no data (e.g. future months in 2026)
            series.append(
                {
                    "year": res["year"],
                    "label": f"{m['label']} {res['year']}",
                    "short": f"{res['year'] % 100:02d}-{m['month']:02d}",
                    "min": m["min_age_days"],
                    "max": m["max_age_days"],
                    "mean": m["avg_age_days"],
                    "median": m["median_age_days"],
                    "n": m["age_sample"],
                    "zero_day": m["zero_day_count"],
                }
            )
    return series


def median_trend(series: list[dict]) -> dict:
    """Fit a simple least-squares line to monthly medians over time.

    Returns slope (days of median change per month), direction text, and the
    first/last medians for a plain-language summary.
    """
    medians = [s["median"] for s in series if s["median"] is not None]
    n = len(medians)
    if n < 2:
        return {"slope": 0.0, "direction": "insufficient data", "first": None, "last": None}
    xs = list(range(n))
    mean_x = sum(xs) / n
    mean_y = sum(medians) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, medians))
    den = sum((x - mean_x) ** 2 for x in xs)
    slope = num / den if den else 0.0
    if slope < -0.5:
        direction = "declining (getting faster to exploit)"
    elif slope > 0.5:
        direction = "rising (slower to exploit)"
    else:
        direction = "roughly flat"
    return {
        "slope": round(slope, 2),
        "direction": direction,
        "first": medians[0],
        "last": medians[-1],
        "overall_median": round(statistics.median(medians), 1),
    }


def print_summary(results: list[dict], source_name: str, total_rows: int) -> None:
    print(f"Source: {source_name}  (total KEV rows: {total_rows})\n")
    for res in results:
        print(f"=== {res['year']} === new KEV: {res['total_kev']}  "
              f"new CVE: {res['total_new_cve']}  ransomware: {res['total_ransomware']}  "
              f"median age: {res['median_age']}d")
        print(f"{'Month':<6}{'newKEV':>8}{'newCVE':>8}{'ransom':>8}{'avgAge':>9}{'medAge':>9}{'n':>5}")
        for m in res["monthly"]:
            aa = "" if m["avg_age_days"] is None else f"{m['avg_age_days']}"
            ma = "" if m["median_age_days"] is None else f"{m['median_age_days']}"
            print(f"{m['label']:<6}{m['new_kev']:>8}{m['new_cve']:>8}"
                  f"{m['ransomware']:>8}{aa:>9}{ma:>9}{m['age_sample']:>5}")
        print()


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_SEV_COLORS = dict(fb.SEVERITY_COLORS)


def _sev_badge(sev: str) -> str:
    sev = (sev or "UNKNOWN").upper()
    color = _SEV_COLORS.get(sev, "#8b98b0")
    return f'<span class="badge" style="background:{color}22;color:{color};border:1px solid {color}55">{html.escape(sev)}</span>'


def _entry_rows_html(entries: list[dict], year: int) -> str:
    out = []
    for e in entries:
        ransom_known = e["ransomware"].strip().lower() == "known"
        ransom = "Yes" if ransom_known else "—"
        age = "—" if e["age_days"] is None else str(e["age_days"])
        desc = html.escape(_truncate(e["nvd_desc"] or e["kev_desc"], 300))
        vp = html.escape(f"{e['vendor']} {e['product']}".strip())
        month = (e["date_added"] or "")[:7]  # YYYY-MM
        sev = (e["severity"] or "UNKNOWN").upper()
        try:
            cvss_val = float(e["score"])
        except (TypeError, ValueError):
            cvss_val = ""
        # data-* attributes drive client-side filtering.
        out.append(
            f'<tr class="kev-row y{year}" '
            f'data-month="{html.escape(month)}" '
            f'data-age="{"" if e["age_days"] is None else e["age_days"]}" '
            f'data-sev="{html.escape(sev)}" '
            f'data-cvss="{cvss_val}" '
            f'data-ransom="{"yes" if ransom_known else "no"}" '
            f'data-vendor="{html.escape((e["vendor"] or "").strip())}" '
            f'data-vp="{html.escape(vp.lower())}">'
            f"<td class='mono'>{html.escape(e['cve_id'])}</td>"
            f"<td>{html.escape(e['date_added'])}</td>"
            f"<td>{html.escape(e['nvd_published'])}</td>"
            f"<td class='num'>{age}</td>"
            f"<td>{_sev_badge(e['severity'])}</td>"
            f"<td class='num'>{html.escape(str(e['score']))}</td>"
            f"<td>{ransom}</td>"
            f"<td>{vp}</td>"
            f"<td class='desc'>{desc}</td>"
            f"</tr>"
        )
    return "\n".join(out)


def _filter_bar(year: int, entries: list[dict]) -> str:
    """Build the filter controls for a year's KEV detail table."""
    months = sorted({(e["date_added"] or "")[:7] for e in entries if e["date_added"]})
    month_opts = "".join(f'<option value="{m}">{m}</option>' for m in months)
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    sev_opts = "".join(f'<option value="{s}">{s.title()}</option>' for s in sevs)
    vendors = sorted(
        {(e["vendor"] or "").strip() for e in entries if (e["vendor"] or "").strip()},
        key=str.lower,
    )
    vendor_opts = "".join(
        f'<option value="{html.escape(v)}">{html.escape(v)}</option>' for v in vendors
    )
    return f"""
      <div class="filters" data-year="{year}">
        <label>Month
          <select data-f="month"><option value="">All</option>{month_opts}</select>
        </label>
        <label>Severity
          <select data-f="sev"><option value="">All</option>{sev_opts}</select>
        </label>
        <label>CVSS
          <select data-f="cvss">
            <option value="">All</option>
            <option value="1-2">1&ndash;2</option>
            <option value="3-4">3&ndash;4</option>
            <option value="5-6">5&ndash;6</option>
            <option value="7-8">7&ndash;8</option>
            <option value="9-10">9&ndash;10</option>
          </select>
        </label>
        <label>Ransomware
          <select data-f="ransom">
            <option value="">All</option><option value="yes">Yes</option><option value="no">No</option>
          </select>
        </label>
        <label>Age min <input type="number" data-f="agemin" style="width:80px" placeholder="e.g. 0"></label>
        <label>Age max <input type="number" data-f="agemax" style="width:80px" placeholder="e.g. 30"></label>
        <label>Vendor
          <select data-f="vendor"><option value="">All</option>{vendor_opts}</select>
        </label>
        <label>Vendor / Product search
          <input type="text" data-f="vp" placeholder="free text" style="width:160px">
        </label>
        <button type="button" data-f="reset">Reset</button>
        <span class="fcount"></span>
      </div>
"""


def _year_section(res: dict) -> str:
    year = res["year"]
    active = _active(res["monthly"])
    chart_data = {
        "labels": [m["label"] for m in active],
        "newKev": [m["new_kev"] for m in active],
        "newCve": [m["new_cve"] for m in active],
        "ransomware": [m["ransomware"] for m in active],
        "avgAge": [m["avg_age_days"] for m in active],
        "medAge": [m["median_age_days"] for m in active],
    }
    detail_rows = _entry_rows_html(res["entries"], year)
    filter_bar = _filter_bar(year, res["entries"])
    return f"""
  <section class="year" id="y{year}">
    <h2 class="yh">{year}</h2>
    <div class="cards">
      <div class="card"><div class="val">{res['total_kev']}</div><div class="lbl">New KEV entries</div></div>
      <div class="card"><div class="val">{res['total_new_cve']}</div><div class="lbl">KEV whose CVE was published in {year}</div></div>
      <div class="card"><div class="val">{res['total_ransomware']}</div><div class="lbl">Linked to ransomware</div></div>
      <div class="card"><div class="val">{res['median_age']}</div><div class="lbl">Median days: published &rarr; exploited</div></div>
    </div>
    <div class="panel">
      <h3>New KEV vs. newly published CVEs, by month</h3>
      <canvas id="counts{year}"></canvas>
    </div>
    <div class="panel">
      <h3>Age: first captured (NVD published) &rarr; exploited (KEV added)</h3>
      <canvas id="age{year}"></canvas>
      <div class="note">Median <b>{res['median_age']} days</b> vs. mean <b>{res['mean_age']} days</b> &mdash;
        the mean is skewed by old CVEs newly exploited this year, so median is the better KRI.</div>
    </div>
    <div class="panel">
      <h3>All {year} KEV entries &mdash; with descriptions ({len(res['entries'])})</h3>
      {filter_bar}
      <div class="tablewrap">
      <table class="detail" id="table{year}">
        <thead><tr>
          <th>CVE</th><th>Added</th><th>Published</th>
          <th class="num">{fb.info("Age (d)", "Days between NVD publication (first captured) and the date CISA added the CVE to KEV (exploited). Negative means exploited before it was published.")}</th>
          <th>{fb.info("Severity", "NVD's CVSS severity band: Critical (9.0-10), High (7.0-8.9), Medium (4.0-6.9), Low (0.1-3.9).")}</th>
          <th class="num">{fb.info("CVSS", "Common Vulnerability Scoring System base score, 0-10. Rates how severe a vulnerability is from exploitability and impact. Higher = more dangerous. From the best available NVD metric (v4.0 &gt; v3.1 &gt; v3.0 &gt; v2).")}</th>
          <th>Ransom</th><th>Vendor / Product</th><th>Description</th>
        </tr></thead>
        <tbody>{detail_rows}</tbody>
      </table>
      </div>
    </div>
  </section>
  <script>CHART_DATA[{year}] = {json.dumps(chart_data)};</script>
"""


def _age_stats_section(series: list[dict], trend: dict, annual: dict) -> str:
    rows = []
    prev_median = None
    for s in series:
        # Arrow vs. previous month's median.
        arrow = ""
        if prev_median is not None and s["median"] is not None:
            if s["median"] < prev_median:
                arrow = f'<span style="color:{fb.ACCENT_GREEN}">&darr;</span>'
            elif s["median"] > prev_median:
                arrow = f'<span style="color:{fb.ACCENT_RED}">&uarr;</span>'
            else:
                arrow = f'<span style="color:{fb.ACCENT_GRAY}">&rarr;</span>'
        prev_median = s["median"]
        zd = s["zero_day"]
        zd_cell = f'<b style="color:{fb.ACCENT_RED}">{zd}</b>' if zd else "0"
        rows.append(
            f"<tr><td>{html.escape(s['label'])}</td>"
            f"<td class='num'>{s['n']}</td>"
            f"<td class='num'>{s['min']}</td>"
            f"<td class='num'>{s['max']}</td>"
            f"<td class='num'>{s['mean']}</td>"
            f"<td class='num'><b>{s['median']}</b> {arrow}</td>"
            f"<td class='num'>{zd_cell}</td></tr>"
        )
    rows_html = "\n".join(rows)

    trend_data = {
        "labels": [s["short"] for s in series],
        "median": [s["median"] for s in series],
        "mean": [s["mean"] for s in series],
    }
    # Annual medians (pooled per-CVE) tell a cleaner story than the noisy monthly series.
    annual_txt = "; ".join(f"{y}: <b>{v} days</b>" for y, v in annual.items())
    return f"""
  <section class="year" id="agestats">
    <h2 class="yh">Time-to-exploitation by month &mdash; min / max / mean / median</h2>
    <div class="note">
      <b>Has the median been getting lower?</b> At the <em>monthly</em> level the median is
      noisy (swinging between single digits and 200+ days), so a straight-line fit across all
      months is essentially flat (slope {trend['slope']} days/month). At the <em>annual</em>
      level, though, the median has dropped &mdash; {annual_txt}. So the honest read is:
      <b>no clean monthly downtrend, but a real year-over-year decline</b> in typical
      time-to-exploitation. The mean runs far above the median because a handful of very old
      CVEs get newly exploited each month, so median is the better indicator.
      The <b>Zero-day (&le;0)</b> column counts records whose time-to-exploit is <b>0 or negative</b>
      &mdash; CISA added the CVE to KEV on or before the day NVD published it, indicating
      exploitation at (or before) public disclosure.
    </div>
    <div class="panel">
      <h3>Monthly median vs. mean age (chronological, 2025 &rarr; 2026)</h3>
      <canvas id="trendChart"></canvas>
    </div>
    <div class="panel">
      <h3>Monthly age statistics (days)</h3>
      <div class="tablewrap">
      <table class="detail">
        <thead><tr>
          <th>Month</th>
          <th class="num">{fb.info("n", "Number of KEV entries added that month that also have an NVD publication date, so an age could be computed.")}</th>
          <th class="num">Min</th>
          <th class="num">Max</th>
          <th class="num">{fb.info("Mean", "Average days from NVD publication to KEV listing. Skewed upward by a few very old CVEs newly exploited, so it runs far above the median.")}</th>
          <th class="num">{fb.info("Median", "The middle value of days-to-exploitation for that month. More representative of the typical case than the mean; the preferred KRI.")}</th>
          <th class="num">{fb.info("Zero-day (&le;0)", "Count of entries added to CISA KEV on or before the CVE was published in NVD (age of 0 or negative) - i.e. exploited at or before public disclosure. A strong zero-day signal.")}</th>
        </tr></thead>
        <tbody>{rows_html}</tbody>
      </table>
      </div>
    </div>
    <script>CHART_DATA.trend = {json.dumps(trend_data)};</script>
  </section>
"""


def render_html(results: list[dict], source_name: str, total_rows: int) -> str:
    series = build_age_stats_series(results)
    trend = median_trend(series)
    annual = {r["year"]: r["median_age"] for r in results}
    age_section = _age_stats_section(series, trend, annual)
    sections = age_section + "\n".join(_year_section(r) for r in results)
    years_js = json.dumps([r["year"] for r in results])
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KEV Enriched EDA &mdash; {" &amp; ".join(str(r['year']) for r in results)}</title>
{fb.FONT_IMPORT}
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>const CHART_DATA = {{}};</script>
<style>
{fb.base_css()}
  .year {{ margin-top:34px; }}
  .yh {{ font-size:22px; border-bottom:2px solid var(--yellow); padding-bottom:6px; }}
  td.mono {{ font-family:ui-monospace,Consolas,monospace; white-space:nowrap; color:var(--core); }}
  td.desc {{ min-width:340px; color:var(--body); }}
  nav.jump {{ margin-top:10px; }}
  nav.jump a {{ color:#cdd8ea; margin-right:14px; text-decoration:none; font-size:13px; }}
  nav.jump a:hover {{ color:#fff; }}
  .defgrid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:16px; margin:18px 0; }}
  .defcard {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:18px 22px;
    box-shadow:0 1px 2px rgba(16,36,66,.05); }}
  .defcard h3 {{ margin:0 0 10px; font-size:16px; color:var(--accent); }}
  .defcard p {{ margin:0 0 10px; color:var(--body); font-size:14px; }}
</style>
</head>
<body>
{fb.brand_header(
    "CISA KEV &times; NVD &mdash; Exploratory Analysis",
    f"Source: <code style='background:rgba(255,255,255,.12);color:#fff'>{html.escape(source_name)}</code> &middot; {total_rows} total KEV records",
)}
<div style="background:var(--core);padding:0 40px 18px"><nav class="jump">Jump to: <a href="#defs">Definitions</a> {" ".join(f'<a href="#y{r["year"]}">{r["year"]}</a>' for r in results)}</nav></div>
<main>
  <section class="year" id="defs">
    <h2 class="yh">Definitions</h2>
    <div class="defgrid">
      <div class="defcard">
        <h3>CVE &mdash; Common Vulnerabilities and Exposures</h3>
        <p>A standardized public identifier for a single known security vulnerability, written as
        <code>CVE-YYYY-NNNNN</code> (e.g. <code>CVE-2021-44228</code>). The program is run by MITRE
        and sponsored by CISA; each CVE names one specific flaw in software or hardware.</p>
        <p>NIST's <b>National Vulnerability Database (NVD)</b> enriches every CVE with a severity
        score (CVSS), weakness type (CWE), affected products, and references. There are
        <b>hundreds of thousands</b> of CVEs, ranging from trivial to critical &mdash; and the large
        majority are never known to be exploited.</p>
      </div>
      <div class="defcard">
        <h3>KEV &mdash; Known Exploited Vulnerabilities</h3>
        <p>CISA's authoritative catalog of the specific CVEs that have been
        <b>confirmed exploited in the wild</b> by attackers. It is a small, curated subset of all
        CVEs (~1,700 vs. hundreds of thousands). To be listed, CISA requires a CVE ID, reliable
        evidence of active exploitation, and a clear remediation.</p>
        <p>Each KEV entry adds exploitation-focused fields a plain CVE lacks: the date CISA added it
        (<code>date_added</code>), a federal remediation <code>due_date</code>, and whether it is
        tied to a known ransomware campaign.</p>
      </div>
    </div>
    <div class="note">
      <b>Relationship:</b> every KEV entry <em>is</em> a CVE &mdash; but only the small fraction that
      attackers are actively using. In short: <b>CVE</b> = &ldquo;a known vulnerability exists&rdquo;;
      <b>KEV</b> = &ldquo;this vulnerability is being exploited right now &mdash; patch it urgently.&rdquo;
      This report joins the two: KEV tells us <em>what is being exploited</em>, NVD/CVE tells us
      <em>how severe it is and what it affects</em>.
    </div>
  </section>
{sections}
  <div class="foot">Generated by <code>analysis/eda_kev.py</code>. &ldquo;Age&rdquo; = KEV date_added &minus; NVD published date, in days.
    Descriptions prefer the NVD writeup, falling back to CISA's KEV summary. Months with no KEV additions are omitted from charts.</div>
</main>
<script>
const grid="{fb.LINE}", muted="{fb.ACCENT_GRAY}";
{fb.chart_theme_js()}
for (const year of {years_js}) {{
  const D = CHART_DATA[year];
  new Chart(document.getElementById('counts'+year), {{
    type:'bar',
    data:{{ labels:D.labels, datasets:[
      {{ label:'New KEV entries', data:D.newKev, backgroundColor:'{fb.CORE_BLUE}' }},
      {{ label:'New CVEs (published that year)', data:D.newCve, backgroundColor:'{fb.ACCENT_BLUE}' }},
      {{ label:'Ransomware-linked', data:D.ransomware, backgroundColor:'{fb.ACCENT_RED}' }}
    ]}},
    options:{{ responsive:true, scales:{{ x:{{grid:{{color:grid}}}}, y:{{grid:{{color:grid}},beginAtZero:true}} }},
      plugins:{{ legend:{{position:'bottom'}} }} }}
  }});
  new Chart(document.getElementById('age'+year), {{
    type:'line',
    data:{{ labels:D.labels, datasets:[
      {{ label:'Average age (days)', data:D.avgAge, borderColor:'{fb.ACCENT_GRAY}', backgroundColor:'{fb.ACCENT_GRAY}22', tension:.3, spanGaps:true }},
      {{ label:'Median age (days)', data:D.medAge, borderColor:'{fb.ACCENT_BLUE}', backgroundColor:'{fb.ACCENT_BLUE}22', tension:.3, spanGaps:true }}
    ]}},
    options:{{ responsive:true, scales:{{ x:{{grid:{{color:grid}}}}, y:{{grid:{{color:grid}},beginAtZero:true,title:{{display:true,text:'days'}}}} }},
      plugins:{{ legend:{{position:'bottom'}} }} }}
  }});
}}

// Combined 2025->2026 median/mean trend.
if (CHART_DATA.trend) {{
  const T = CHART_DATA.trend;
  new Chart(document.getElementById('trendChart'), {{
    type:'line',
    data:{{ labels:T.labels, datasets:[
      {{ label:'Median age (days)', data:T.median, borderColor:'{fb.ACCENT_BLUE}', backgroundColor:'{fb.ACCENT_BLUE}22', tension:.25, borderWidth:2.5, spanGaps:true }},
      {{ label:'Mean age (days)', data:T.mean, borderColor:'{fb.ACCENT_GRAY}', backgroundColor:'{fb.ACCENT_GRAY}22', borderDash:[5,4], tension:.25, spanGaps:true }}
    ]}},
    options:{{ responsive:true, scales:{{ x:{{grid:{{color:grid}}}}, y:{{grid:{{color:grid}},beginAtZero:true,title:{{display:true,text:'days'}}}} }},
      plugins:{{ legend:{{position:'bottom'}} }} }}
  }});
}}

// --- KEV detail table filtering (per year) ---
function cvssInBand(val, band) {{
  if (band === "" || val === "" || val === null) return band === "";
  const v = parseFloat(val);
  if (isNaN(v)) return false;
  const [lo, hi] = band.split('-').map(Number);
  return v >= lo && v <= hi;
}}

document.querySelectorAll('.filters').forEach(function(bar) {{
  const year = bar.getAttribute('data-year');
  const rows = Array.from(document.querySelectorAll('#table' + year + ' tbody tr'));
  const controls = bar.querySelectorAll('[data-f]');
  const countEl = bar.querySelector('.fcount');

  function val(name) {{
    const el = bar.querySelector('[data-f="' + name + '"]');
    return el ? el.value.trim() : "";
  }}

  function apply() {{
    const fMonth = val('month'), fSev = val('sev'), fCvss = val('cvss'),
          fRansom = val('ransom'), fVp = val('vp').toLowerCase(), fVendor = val('vendor');
    const fMin = val('agemin'), fMax = val('agemax');
    let shown = 0;
    rows.forEach(function(r) {{
      const age = r.getAttribute('data-age');
      const ageNum = age === "" ? null : parseFloat(age);
      let ok = true;
      if (fMonth && r.getAttribute('data-month') !== fMonth) ok = false;
      if (fSev && r.getAttribute('data-sev') !== fSev) ok = false;
      if (fCvss && !cvssInBand(r.getAttribute('data-cvss'), fCvss)) ok = false;
      if (fRansom && r.getAttribute('data-ransom') !== fRansom) ok = false;
      if (fVendor && r.getAttribute('data-vendor') !== fVendor) ok = false;
      if (fVp && r.getAttribute('data-vp').indexOf(fVp) === -1) ok = false;
      if (fMin !== "" && (ageNum === null || ageNum < parseFloat(fMin))) ok = false;
      if (fMax !== "" && (ageNum === null || ageNum > parseFloat(fMax))) ok = false;
      r.style.display = ok ? "" : "none";
      if (ok) shown++;
    }});
    countEl.textContent = shown + " of " + rows.length + " shown";
  }}

  controls.forEach(function(c) {{
    if (c.getAttribute('data-f') === 'reset') {{
      c.addEventListener('click', function() {{
        bar.querySelectorAll('select').forEach(s => s.value = "");
        bar.querySelectorAll('input').forEach(i => i.value = "");
        apply();
      }});
    }} else {{
      c.addEventListener('input', apply);
      c.addEventListener('change', apply);
    }}
  }});
  apply();
}});
</script>
</body>
</html>
"""


def write_report() -> Path:
    src = _latest_enriched()
    rows = load_rows(src)
    results = [compute_year(rows, y) for y in YEARS]
    print_summary(results, src.name, len(rows))

    series = build_age_stats_series(results)
    trend = median_trend(series)
    print("Age stats by month (days):")
    print(f"{'Month':<10}{'n':>5}{'min':>7}{'max':>8}{'mean':>9}{'median':>9}{'zeroDay':>9}")
    total_zd = 0
    for s in series:
        total_zd += s["zero_day"]
        print(f"{s['label']:<10}{s['n']:>5}{s['min']:>7}{s['max']:>8}{s['mean']:>9}{s['median']:>9}{s['zero_day']:>9}")
    print(f"Total zero-day (<=0) records: {total_zd}")
    print(f"\nMedian trend: {trend['direction']} "
          f"(slope {trend['slope']} days/month; first {trend['first']} -> last {trend['last']})")

    html_text = render_html(results, src.name, len(rows))
    out = DATA_DIR / "kev_eda.html"
    out.write_text(html_text, encoding="utf-8")
    return out


if __name__ == "__main__":
    out = write_report()
    print(f"HTML report written to {out}")
