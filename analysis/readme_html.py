"""Render README.md as a FINRA-branded HTML page (reports/readme.html).

Uses a small, dependency-free Markdown subset covering what the README uses:
headings, fenced code blocks, inline code, bold, links, blockquotes, and
unordered lists. Wraps the result in the shared FINRA brand chrome.

Usage:  python analysis/readme_html.py
Output: reports/readme.html
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import finra_brand as fb  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
OUT = ROOT / "reports" / "readme.html"


def _inline(text: str) -> str:
    """Apply inline markdown (escape first, then code/bold/links)."""
    text = html.escape(text)
    # Inline code: `code`
    text = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", text)
    # Bold: **text**
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    # Italic: *text* (avoid matching ** already handled)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<em>\1</em>", text)
    # Links: [label](url)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        lambda m: f'<a href="{m.group(2)}" target="_blank" rel="noopener">{m.group(1)}</a>',
        text,
    )
    # Autolinks: <https://...>
    text = re.sub(
        r"&lt;(https?://[^&]+)&gt;",
        lambda m: f'<a href="{m.group(1)}" target="_blank" rel="noopener">{m.group(1)}</a>',
        text,
    )
    return text


def md_to_html(md: str) -> str:
    lines = md.splitlines()
    out: list[str] = []
    i = 0
    in_list = False

    def close_list():
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while i < len(lines):
        line = lines[i]

        # Fenced code block
        if line.strip().startswith("```"):
            close_list()
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(html.escape(lines[i]))
                i += 1
            i += 1  # skip closing fence
            out.append('<pre><code>' + "\n".join(code) + "</code></pre>")
            continue

        # Headings
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            close_list()
            level = len(m.group(1))
            out.append(f"<h{level}>{_inline(m.group(2))}</h{level}>")
            i += 1
            continue

        # Blockquote
        if line.startswith(">"):
            close_list()
            quote = [line]
            while i + 1 < len(lines) and lines[i + 1].startswith(">"):
                i += 1
                quote.append(lines[i])
            body = " ".join(q.lstrip("> ").rstrip() for q in quote)
            out.append(f'<blockquote>{_inline(body)}</blockquote>')
            i += 1
            continue

        # Unordered list item
        lm = re.match(r"^[-*]\s+(.*)$", line)
        if lm:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(lm.group(1))}</li>")
            i += 1
            continue

        # Blank line
        if not line.strip():
            close_list()
            i += 1
            continue

        # Paragraph (accumulate consecutive non-empty, non-special lines)
        close_list()
        para = [line]
        while i + 1 < len(lines) and lines[i + 1].strip() and not re.match(
            r"^(#{1,4}\s|[-*]\s|>|```)", lines[i + 1]
        ):
            i += 1
            para.append(lines[i])
        out.append(f"<p>{_inline(' '.join(para))}</p>")
        i += 1

    close_list()
    return "\n".join(out)


def build() -> Path:
    md = README.read_text(encoding="utf-8")
    body = md_to_html(md)
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Documentation | Cyber Risk KRIs | FINRA</title>
{fb.FONT_IMPORT}
<style>
{fb.base_css()}
  main {{ max-width:900px; }}
  .doc h1 {{ font-size:24px; margin:26px 0 10px; }}
  .doc h2 {{ font-size:20px; margin:30px 0 10px; border-bottom:2px solid var(--yellow); padding-bottom:6px; }}
  .doc h3 {{ font-size:16px; margin:22px 0 8px; }}
  .doc p {{ margin:10px 0; }}
  .doc ul {{ margin:10px 0; padding-left:22px; }}
  .doc li {{ margin:4px 0; }}
  .doc pre {{ background:#0f1b2e; color:#e6ebf5; border:1px solid var(--line); border-radius:8px;
    padding:14px 16px; overflow-x:auto; font-size:13px; line-height:1.5; }}
  .doc pre code {{ background:none; padding:0; color:inherit; font-size:13px; }}
  .doc code {{ background:#eef1f5; color:var(--core); padding:1px 6px; border-radius:4px; font-size:.92em; }}
  .doc blockquote {{ margin:14px 0; padding:12px 16px; background:#eef3fa;
    border-left:4px solid var(--accent); border-radius:4px; color:#2b3a52; font-size:14px; }}
  .doc a {{ color:var(--accent); }}
  .backlink {{ display:inline-block; margin-bottom:6px; color:#cdd8ea; text-decoration:none; font-size:13px; }}
  .backlink:hover {{ color:#fff; }}
</style>
</head>
<body>
{fb.brand_header("Cyber Risk KRIs &mdash; Documentation", "Project README &middot; collectors, enrichment, and reports")}
<div style="background:var(--core);padding:0 40px 16px"><a class="backlink" href="index.html">&larr; Back to reports</a></div>
<main>
  <div class="doc">
{body}
  </div>
  <div class="foot">Rendered from <code>README.md</code> by <code>analysis/readme_html.py</code>.</div>
</main>
</body>
</html>
"""
    OUT.write_text(page, encoding="utf-8")
    return OUT


if __name__ == "__main__":
    out = build()
    print(f"Wrote {out}")
