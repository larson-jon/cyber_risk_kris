"""Shared FINRA brand assets for the HTML reports.

Centralizes the FINRA color palette, typography, chart colors, and common
page chrome (yellow top rule, header with wordmark, footer) so every report
renders consistently against the brand guidelines.

Note on the logo: the FINRA brand guidelines prohibit recreating the logo in a
different typeface for official/external use. We do not have the official logo
artwork here, so the header uses a plain wordmark placeholder. Drop the official
FINRA logo SVG/PNG into ``reports/`` and swap ``brand_header`` to reference it
before any external distribution.
"""

from __future__ import annotations

# --- FINRA color palette (from brand guidelines, page 16) ------------------
CORE_BLUE = "#233E66"     # PMS 541 U  -- primary
ACCENT_BLUE = "#0082D1"   # PMS Process Cyan U
ACCENT_GRAY = "#595959"   # PMS Warm Gray U
ACCENT_GREEN = "#9EC405"  # PMS 390 U
ACCENT_YELLOW = "#FFCF40" # PMS 7404 U
ACCENT_RED = "#FB483D"    # PMS Warm Red U

# Neutral support tones for a light, bright layout (per photography/voice guidance).
INK = "#1a1a1a"
BODY = "#333333"
MUTED = "#6b7280"
LINE = "#e2e6ec"
PANEL = "#ffffff"
PAGE_BG = "#f4f6f9"

# Severity / categorical chart colors mapped onto the brand palette.
SEVERITY_COLORS = {
    "CRITICAL": ACCENT_RED,
    "HIGH": "#f2872f",       # warm orange bridge (brand-adjacent)
    "MEDIUM": ACCENT_YELLOW,
    "LOW": ACCENT_GREEN,
    "UNKNOWN": ACCENT_GRAY,
}

# Google Fonts import for Open Sans (+ Condensed via 800 weight) and Lora.
FONT_IMPORT = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link href="https://fonts.googleapis.com/css2?'
    "family=Open+Sans:wght@400;600;700;800&"
    "family=Lora:ital,wght@0,400;0,600;1,400&display=swap\" rel=\"stylesheet\">"
)


def base_css() -> str:
    """Return the shared FINRA CSS block (no surrounding <style> tags)."""
    return f"""
  :root {{
    --core:{CORE_BLUE}; --accent:{ACCENT_BLUE}; --gray:{ACCENT_GRAY};
    --green:{ACCENT_GREEN}; --yellow:{ACCENT_YELLOW}; --red:{ACCENT_RED};
    --ink:{INK}; --body:{BODY}; --muted:{MUTED}; --line:{LINE};
    --panel:{PANEL}; --bg:{PAGE_BG};
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--body);
    font-family:'Open Sans',-apple-system,Segoe UI,Roboto,Arial,sans-serif;
    font-size:15px; line-height:1.6; }}
  /* White band carrying the official black FINRA logo. */
  .logoband {{ background:#fff; padding:18px 40px; }}
  .logo {{ height:52px; width:auto; display:block; }}
  /* FINRA yellow top rule echoing the brand cover. */
  .brandbar {{ height:6px; background:var(--yellow); }}
  header.brand {{ background:var(--core); color:#fff; padding:24px 40px 24px; }}
  header.brand h1 {{ font-family:'Open Sans',sans-serif; font-weight:800;
    margin:14px 0 4px; font-size:26px; color:#fff; }}
  header.brand .sub {{ color:#cdd8ea; font-size:14px; }}
  header.brand .tagline {{ color:#9db4d6; font-size:12px; margin-top:8px;
    font-family:'Lora',Georgia,serif; font-style:italic; }}
  h2,h3 {{ font-family:'Open Sans',sans-serif; font-weight:800; color:var(--core); }}
  main {{ padding:22px 40px 60px; max-width:1200px; margin:0 auto; }}
  a {{ color:var(--accent); }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin:20px 0; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
    padding:16px 18px; box-shadow:0 1px 2px rgba(16,36,66,.05); }}
  .card .val {{ font-size:28px; font-weight:800; color:var(--core); }}
  .card .lbl {{ color:var(--muted); font-size:13px; margin-top:4px; }}
  .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:10px;
    padding:18px 22px; margin:18px 0; box-shadow:0 1px 2px rgba(16,36,66,.05); }}
  .panel h3 {{ margin:0 0 14px; font-size:16px; }}
  canvas {{ max-height:320px; }}
  .note {{ background:#eef3fa; border-left:4px solid var(--accent); border-radius:4px;
    padding:12px 16px; color:#2b3a52; font-size:13px; margin:14px 0; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ padding:9px 11px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }}
  thead th {{ position:sticky; top:0; background:var(--core); color:#fff; font-weight:600; }}
  td.num, th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  tbody tr:nth-child(even) {{ background:#f7f9fc; }}
  .tablewrap {{ overflow-x:auto; max-height:540px; overflow-y:auto; border:1px solid var(--line); border-radius:8px; }}
  .badge {{ padding:1px 8px; border-radius:12px; font-size:11px; font-weight:700; white-space:nowrap; }}
  .filters {{ display:flex; flex-wrap:wrap; gap:12px 16px; align-items:flex-end;
    background:#eef3fa; border:1px solid var(--line); border-radius:10px; padding:12px 16px; margin-bottom:14px; }}
  .filters label {{ display:flex; flex-direction:column; gap:4px; font-size:12px; color:var(--core); font-weight:600; }}
  .filters select, .filters input {{ background:#fff; color:var(--ink);
    border:1px solid var(--line); border-radius:6px; padding:6px 8px; font-size:13px; font-weight:400; }}
  .filters button {{ background:var(--core); color:#fff; border:none;
    border-radius:6px; padding:8px 15px; font-size:13px; cursor:pointer; font-weight:600; }}
  .filters button:hover {{ background:#1a2f4d; }}
  .fcount {{ color:var(--muted); font-size:13px; margin-left:auto; align-self:center; }}
  .foot {{ color:var(--muted); font-size:12px; margin-top:30px; border-top:1px solid var(--line); padding-top:14px; }}
  code {{ background:#eef1f5; padding:1px 6px; border-radius:4px; font-size:.92em; }}
""" + _TOOLTIP_CSS


# Official FINRA Enterprise Risk Management logo, expected alongside each report
# (copied into both data/ and reports/). It is the black version, so it sits on
# a white band per brand guidance (logo must be white/reversed on dark).
LOGO_FILE = "finra%20logo.png"


def info(label: str, definition: str) -> str:
    """Return ``label`` followed by an (i) marker with a hover tooltip.

    Works in table headers and inline text. Uses a CSS-only tooltip (no JS) so it
    functions in any static HTML context.
    """
    import html as _html

    return (
        f'{label} <span class="info" tabindex="0" aria-label="{_html.escape(definition)}">'
        f'i<span class="tip">{_html.escape(definition)}</span></span>'
    )


# CSS for the info tooltip -- appended into base_css().
_TOOLTIP_CSS = """
  .info {{ display:inline-flex; align-items:center; justify-content:center;
    width:14px; height:14px; border-radius:50%; background:{accent}; color:#fff;
    font-size:9px; font-weight:700; font-style:normal; cursor:help; margin-left:4px;
    vertical-align:middle; position:relative; font-family:'Open Sans',sans-serif; }}
  .info .tip {{ visibility:hidden; opacity:0; position:absolute; z-index:20;
    bottom:150%; left:50%; transform:translateX(-50%); width:250px;
    background:{core}; color:#fff; text-align:left; font-weight:400; font-size:12px;
    line-height:1.45; padding:9px 11px; border-radius:6px; box-shadow:0 4px 14px rgba(16,36,66,.25);
    transition:opacity .12s; pointer-events:none; white-space:normal; text-transform:none; }}
  .info .tip::after {{ content:""; position:absolute; top:100%; left:50%; margin-left:-5px;
    border:5px solid transparent; border-top-color:{core}; }}
  .info:hover .tip, .info:focus .tip {{ visibility:visible; opacity:1; }}
  thead th .info .tip {{ font-weight:400; }}
""".format(accent=ACCENT_BLUE, core=CORE_BLUE)


def brand_header(title: str, subtitle: str = "", tagline: bool = True) -> str:
    """Return the logo band + yellow rule + Core Blue header block.

    The black FINRA logo is placed on a white band (not on the blue) so it stays
    legible and unaltered, respecting the brand's dark-background rule.
    """
    tag = (
        '<div class="tagline">Investor protection. Market integrity.</div>'
        if tagline
        else ""
    )
    sub = f'<div class="sub">{subtitle}</div>' if subtitle else ""
    return f"""<div class="logoband">
  <img class="logo" src="{LOGO_FILE}" alt="FINRA Enterprise Risk Management">
</div>
<div class="brandbar"></div>
<header class="brand">
  <h1>{title}</h1>
  {sub}
  {tag}
</header>"""


def chart_theme_js() -> str:
    """Chart.js global defaults matching the brand (light theme)."""
    return f"""
Chart.defaults.color = '{ACCENT_GRAY}';
Chart.defaults.borderColor = '{LINE}';
Chart.defaults.font.family = "'Open Sans', system-ui, sans-serif";
"""
