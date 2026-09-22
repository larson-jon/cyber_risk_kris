"""Advisory dashboard for SEC 8-K cyber-incident filings (Item 1.05 & 8.01).

Reads the latest data/edgar_8k_cyber_*.csv (produced by
`python -m collectors.cli edgar --item both`) and builds a self-contained HTML
dashboard aimed at a cyber-security advisor: monthly incident trend, disclosure
type split, third-party / supply-chain share, industry breakdown, incident-type
mix, affected data types, and a filterable table of the incident narratives.

Usage:  python analysis/edgar_dashboard.py
Output: data/edgar_dashboard.html
"""

from __future__ import annotations

import csv
import glob
import html
import json
from collections import Counter
from pathlib import Path

DATA_DIR = Path("data")


def _latest_edgar() -> Path:
    files = sorted(glob.glob(str(DATA_DIR / "edgar_8k_cyber_*.csv")))
    if not files:
        # Fall back to single-item exports if the combined file isn't present.
        files = sorted(glob.glob(str(DATA_DIR / "edgar_8k_*.csv")))
    if not files:
        raise SystemExit(
            "No edgar_8k_*.csv found in data/. Run: "
            "python -m collectors.cli edgar --item both"
        )
    return Path(files[-1])


def load_rows(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def _month(d: str) -> str:
    return (d or "")[:7]


def _counter_to_sorted(c: Counter, top: int | None = None) -> list[tuple[str, int]]:
    items = sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))
    return items[:top] if top else items


def compute(rows: list[dict]) -> dict:
    months = sorted({_month(r["filing_date"]) for r in rows if r["filing_date"]})
    by_month_105 = Counter()
    by_month_801 = Counter()
    industries = Counter()
    incident_types = Counter()
    statuses = Counter()
    third_party = Counter()
    data_types = Counter()
    theme_counts = Counter()

    for r in rows:
        m = _month(r["filing_date"])
        if r["disclosure_type"] == "1.05":
            by_month_105[m] += 1
        else:
            by_month_801[m] += 1
        industries[r.get("industry") or "Unknown"] += 1
        incident_types[r.get("incident_type") or "Unspecified"] += 1
        statuses[r.get("status") or "Reported"] += 1
        third_party[r.get("third_party") or "No"] += 1
        for dt in (r.get("data_types") or "").split(";"):
            dt = dt.strip()
            if dt:
                data_types[dt] += 1
        for th in (r.get("themes") or "").split(";"):
            th = th.strip()
            if th:
                theme_counts[th] += 1

    return {
        "total": len(rows),
        "count_105": sum(by_month_105.values()),
        "count_801": sum(by_month_801.values()),
        "months": months,
        "monthly_105": [by_month_105.get(m, 0) for m in months],
        "monthly_801": [by_month_801.get(m, 0) for m in months],
        "industries": _counter_to_sorted(industries),
        "incident_types": _counter_to_sorted(incident_types),
        "statuses": _counter_to_sorted(statuses),
        "third_party_yes": third_party.get("Yes", 0),
        "third_party_no": third_party.get("No", 0),
        "data_types": _counter_to_sorted(data_types),
        "themes": _counter_to_sorted(theme_counts),
    }


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_TYPE_COLORS = {
    "Ransomware": "#f9536b",
    "Vendor / supply-chain": "#b06cf9",
    "Data theft": "#f9903e",
    "Operational disruption": "#4f9cf9",
    "Unauthorized access": "#5fd08a",
    "Unspecified": "#8b98b0",
}


def _row_html(r: dict) -> str:
    tp = r.get("third_party") == "Yes"
    tp_cell = '<span class="pill tp">Vendor</span>' if tp else "&mdash;"
    itype = r.get("incident_type") or "Unspecified"
    color = _TYPE_COLORS.get(itype, "#8b98b0")
    dtypes = html.escape(r.get("data_types") or "")
    return (
        f'<tr class="frow" '
        f'data-type="{html.escape(r["disclosure_type"])}" '
        f'data-itype="{html.escape(itype)}" '
        f'data-industry="{html.escape(r.get("industry") or "")}" '
        f'data-tp="{"yes" if tp else "no"}" '
        f'data-month="{html.escape(_month(r["filing_date"]))}" '
        f'data-status="{html.escape(r.get("status") or "")}">'
        f'<td>{html.escape(r["filing_date"])}</td>'
        f'<td class="co">{html.escape(r["company"])}'
        f'{" (" + html.escape(r["ticker"]) + ")" if r.get("ticker") else ""}</td>'
        f'<td><span class="pill" style="background:{color}22;color:{color};border:1px solid {color}55">{html.escape(r["disclosure_type"])}</span></td>'
        f'<td><span style="color:{color}">{html.escape(itype)}</span></td>'
        f'<td>{html.escape(r.get("industry") or "")}</td>'
        f'<td class="ctr">{tp_cell}</td>'
        f'<td>{dtypes}</td>'
        f'<td>{html.escape(r.get("status") or "")}</td>'
        f'<td class="desc">{html.escape((r.get("incident_description") or "")[:400])}</td>'
        f'<td><a href="{html.escape(r.get("filing_url") or "")}" target="_blank">filing</a></td>'
        f"</tr>"
    )


def render(rows: list[dict], agg: dict, source_name: str) -> str:
    months = sorted({_month(r["filing_date"]) for r in rows if r["filing_date"]})
    industries = sorted({r.get("industry") or "Unknown" for r in rows})
    itypes = sorted({r.get("incident_type") or "Unspecified" for r in rows})

    tp_total = agg["third_party_yes"] + agg["third_party_no"]
    tp_pct = round(100 * agg["third_party_yes"] / tp_total) if tp_total else 0

    charts = {
        "monthsLabels": agg["months"],
        "monthly105": agg["monthly_105"],
        "monthly801": agg["monthly_801"],
        "industryLabels": [k for k, _ in agg["industries"]],
        "industryData": [v for _, v in agg["industries"]],
        "typeLabels": [k for k, _ in agg["incident_types"]],
        "typeData": [v for _, v in agg["incident_types"]],
        "typeColors": [_TYPE_COLORS.get(k, "#8b98b0") for k, _ in agg["incident_types"]],
        "dataTypeLabels": [k for k, _ in agg["data_types"]],
        "dataTypeData": [v for _, v in agg["data_types"]],
        "tpYes": agg["third_party_yes"],
        "tpNo": agg["third_party_no"],
    }

    def opts(values):
        return "".join(f'<option value="{html.escape(v)}">{html.escape(v)}</option>' for v in values)

    month_opts = opts(months)
    industry_opts = opts(industries)
    itype_opts = opts(itypes)
    table_rows = "\n".join(_row_html(r) for r in rows)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SEC 8-K Cyber-Incident Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
  :root {{ --bg:#0f1420; --panel:#1a2233; --ink:#e6ebf5; --muted:#8b98b0; --grid:#2a3550; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif; }}
  header {{ padding:28px 36px 6px; }}
  h1 {{ margin:0 0 4px; font-size:24px; }}
  .sub {{ color:var(--muted); font-size:14px; }}
  main {{ padding:14px 36px 60px; max-width:1280px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:15px; margin:18px 0; }}
  .card {{ background:var(--panel); border:1px solid var(--grid); border-radius:12px; padding:16px 18px; }}
  .card .val {{ font-size:27px; font-weight:700; }}
  .card .lbl {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; }}
  @media (max-width:900px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
  .panel {{ background:var(--panel); border:1px solid var(--grid); border-radius:12px; padding:18px 20px; margin:18px 0; }}
  .panel h3 {{ margin:0 0 14px; font-size:16px; }}
  canvas {{ max-height:300px; }}
  .note {{ background:#20293d; border-left:3px solid #4f9cf9; border-radius:6px; padding:10px 14px; color:#c7d2e6; font-size:13px; margin:14px 0; }}
  .filters {{ display:flex; flex-wrap:wrap; gap:12px 14px; align-items:flex-end; background:#141b2a; border:1px solid var(--grid); border-radius:10px; padding:12px 16px; margin-bottom:14px; }}
  .filters label {{ display:flex; flex-direction:column; gap:4px; font-size:12px; color:var(--muted); }}
  .filters select, .filters input {{ background:#0c1019; color:var(--ink); border:1px solid var(--grid); border-radius:6px; padding:6px 8px; font-size:13px; }}
  .filters button {{ background:#2a3550; color:var(--ink); border:1px solid var(--grid); border-radius:6px; padding:7px 14px; cursor:pointer; }}
  .fcount {{ color:var(--muted); font-size:13px; margin-left:auto; align-self:center; }}
  .tablewrap {{ overflow-x:auto; max-height:560px; overflow-y:auto; border:1px solid var(--grid); border-radius:8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ padding:8px 10px; border-bottom:1px solid var(--grid); text-align:left; vertical-align:top; }}
  thead th {{ position:sticky; top:0; background:#141b2a; color:var(--muted); font-weight:600; }}
  td.co {{ font-weight:600; white-space:nowrap; }}
  td.desc {{ min-width:340px; color:#c7d2e6; }}
  td.ctr {{ text-align:center; }}
  .pill {{ padding:1px 8px; border-radius:20px; font-size:11px; font-weight:600; white-space:nowrap; }}
  .pill.tp {{ background:#b06cf922; color:#b06cf9; border:1px solid #b06cf955; }}
  a {{ color:#4f9cf9; }}
</style>
</head>
<body>
<header>
  <h1>SEC 8-K Cyber-Incident Dashboard</h1>
  <div class="sub">Source: <code>{html.escape(source_name)}</code> &middot; material (Item 1.05) &amp; voluntary (Item 8.01) disclosures</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="val">{agg['total']}</div><div class="lbl">Total cyber filings</div></div>
    <div class="card"><div class="val">{agg['count_105']}</div><div class="lbl">Item 1.05 (material)</div></div>
    <div class="card"><div class="val">{agg['count_801']}</div><div class="lbl">Item 8.01 (voluntary)</div></div>
    <div class="card"><div class="val">{tp_pct}%</div><div class="lbl">Involved a third party / vendor</div></div>
  </div>

  <div class="note">
    <b>What this adds over CVE/KEV:</b> KEV tells you which vulnerabilities are exploited somewhere; this shows
    which <b>named public companies</b> actually suffered a material incident, in which <b>industries</b>, via what
    <b>mechanism</b> (notably supply-chain), and where each stands (investigating, contained, litigation).
    Incident type / third-party / data-type tags are derived from the filing text by keyword rules &mdash; a
    starting classification, not a substitute for reading the narrative.
  </div>

  <div class="panel">
    <h3>Cyber filings by month</h3>
    <canvas id="trend"></canvas>
  </div>

  <div class="grid2">
    <div class="panel"><h3>Incident type</h3><canvas id="itype"></canvas></div>
    <div class="panel"><h3>Third-party / supply-chain involvement</h3><canvas id="tp"></canvas></div>
  </div>
  <div class="grid2">
    <div class="panel"><h3>Industry (by SIC)</h3><canvas id="industry"></canvas></div>
    <div class="panel"><h3>Affected data types</h3><canvas id="dtype"></canvas></div>
  </div>

  <div class="panel">
    <h3>Incident filings &mdash; filterable</h3>
    <div class="filters" id="fbar">
      <label>Disclosure
        <select data-f="type"><option value="">All</option><option value="1.05">1.05</option><option value="8.01">8.01</option></select>
      </label>
      <label>Incident type <select data-f="itype"><option value="">All</option>{itype_opts}</select></label>
      <label>Industry <select data-f="industry"><option value="">All</option>{industry_opts}</select></label>
      <label>Third party <select data-f="tp"><option value="">All</option><option value="yes">Yes</option><option value="no">No</option></select></label>
      <label>Month <select data-f="month"><option value="">All</option>{month_opts}</select></label>
      <label>Search <input type="text" data-f="q" placeholder="company or text" style="width:180px"></label>
      <button type="button" data-f="reset">Reset</button>
      <span class="fcount"></span>
    </div>
    <div class="tablewrap">
    <table id="ftable">
      <thead><tr>
        <th>Date</th><th>Company</th><th>Item</th><th>Incident type</th><th>Industry</th>
        <th>Vendor</th><th>Data</th><th>Status</th><th>Description</th><th></th>
      </tr></thead>
      <tbody>{table_rows}</tbody>
    </table>
    </div>
  </div>

  <div class="foot" style="color:var(--muted);font-size:12px;margin-top:24px">
    Generated by <code>analysis/edgar_dashboard.py</code>. Tags are keyword-derived from filing text.
  </div>
</main>
<script>
const C = {json.dumps(charts)};
const grid="#2a3550", muted="#8b98b0";
Chart.defaults.color = muted;
Chart.defaults.font.family = "Segoe UI, system-ui, sans-serif";

new Chart(document.getElementById('trend'), {{
  type:'bar',
  data:{{ labels:C.monthsLabels, datasets:[
    {{ label:'Item 1.05 (material)', data:C.monthly105, backgroundColor:'#f9536b' }},
    {{ label:'Item 8.01 (voluntary)', data:C.monthly801, backgroundColor:'#4f9cf9' }}
  ]}},
  options:{{ responsive:true, scales:{{ x:{{stacked:true,grid:{{color:grid}}}}, y:{{stacked:true,beginAtZero:true,grid:{{color:grid}}}} }},
    plugins:{{ legend:{{position:'bottom'}} }} }}
}});

new Chart(document.getElementById('itype'), {{
  type:'bar',
  data:{{ labels:C.typeLabels, datasets:[{{ data:C.typeData, backgroundColor:C.typeColors }}]}},
  options:{{ indexAxis:'y', responsive:true, plugins:{{legend:{{display:false}}}},
    scales:{{ x:{{beginAtZero:true,grid:{{color:grid}}}}, y:{{grid:{{color:grid}}}} }} }}
}});

new Chart(document.getElementById('tp'), {{
  type:'doughnut',
  data:{{ labels:['Third-party / vendor','Direct'], datasets:[{{ data:[C.tpYes,C.tpNo], backgroundColor:['#b06cf9','#4f9cf9'] }}]}},
  options:{{ responsive:true, plugins:{{legend:{{position:'bottom'}}}} }}
}});

new Chart(document.getElementById('industry'), {{
  type:'bar',
  data:{{ labels:C.industryLabels, datasets:[{{ data:C.industryData, backgroundColor:'#5fd08a' }}]}},
  options:{{ indexAxis:'y', responsive:true, plugins:{{legend:{{display:false}}}},
    scales:{{ x:{{beginAtZero:true,grid:{{color:grid}}}}, y:{{grid:{{color:grid}}}} }} }}
}});

new Chart(document.getElementById('dtype'), {{
  type:'bar',
  data:{{ labels:C.dataTypeLabels, datasets:[{{ data:C.dataTypeData, backgroundColor:'#f9903e' }}]}},
  options:{{ responsive:true, plugins:{{legend:{{display:false}}}},
    scales:{{ x:{{grid:{{color:grid}}}}, y:{{beginAtZero:true,grid:{{color:grid}}}} }} }}
}});

// --- table filtering ---
(function() {{
  const bar = document.getElementById('fbar');
  const rows = Array.from(document.querySelectorAll('#ftable tbody tr'));
  const countEl = bar.querySelector('.fcount');
  function val(n) {{ const e = bar.querySelector('[data-f="'+n+'"]'); return e ? e.value.trim().toLowerCase() : ""; }}
  function apply() {{
    const ft=val('type'), fi=val('itype'), fin=val('industry'), ftp=val('tp'), fm=val('month'), fq=val('q');
    let shown=0;
    rows.forEach(function(r) {{
      let ok=true;
      if (ft && r.dataset.type.toLowerCase()!==ft) ok=false;
      if (fi && r.dataset.itype.toLowerCase()!==fi) ok=false;
      if (fin && r.dataset.industry.toLowerCase()!==fin) ok=false;
      if (ftp && r.dataset.tp!==ftp) ok=false;
      if (fm && r.dataset.month!==fm) ok=false;
      if (fq && r.textContent.toLowerCase().indexOf(fq)===-1) ok=false;
      r.style.display = ok ? "" : "none";
      if (ok) shown++;
    }});
    countEl.textContent = shown+" of "+rows.length+" shown";
  }}
  bar.querySelectorAll('[data-f]').forEach(function(c) {{
    if (c.dataset.f==='reset') c.addEventListener('click', function() {{
      bar.querySelectorAll('select').forEach(s=>s.value=""); bar.querySelectorAll('input').forEach(i=>i.value=""); apply();
    }});
    else {{ c.addEventListener('input', apply); c.addEventListener('change', apply); }}
  }});
  apply();
}})();
</script>
</body>
</html>
"""


def write_dashboard() -> Path:
    src = _latest_edgar()
    rows = load_rows(src)
    agg = compute(rows)
    out = DATA_DIR / "edgar_dashboard.html"
    out.write_text(render(rows, agg, src.name), encoding="utf-8")
    return out, agg


if __name__ == "__main__":
    out, agg = write_dashboard()
    print(f"Rows: {agg['total']}  (1.05={agg['count_105']}, 8.01={agg['count_801']})")
    print("Top industries:", agg["industries"][:5])
    print("Incident types:", agg["incident_types"])
    print(f"Third-party: {agg['third_party_yes']} yes / {agg['third_party_no']} no")
    print(f"Dashboard written to {out}")
