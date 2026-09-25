"""Fetch and cache per-month NVD *published* CVE counts (total + High/Critical).

The KEV enrichment only ever pulls the ~1,700 exploited CVEs, so it can't tell
you the denominator: how many CVEs were published overall, or how many were
High/Critical severity. This script queries the NVD API's ``pubStartDate`` /
``pubEndDate`` per month for the total and (via ``cvssV3Severity``) the High and
Critical counts, caching them to data/nvd_monthly_totals.json.

The KEV EDA report reads that cache to plot total published CVEs and
High/Critical CVEs (secondary axis) against the tiny exploited (KEV) counts --
the "how few of the many severe CVEs get exploited" context.

Usage:  python analysis/nvd_monthly_totals.py 2025 2026
Output: data/nvd_monthly_totals.json
        {"2025-01": {"total": 12345, "highCritical": 6789}, ...}
"""

from __future__ import annotations

import calendar
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = Path("data") / "nvd_monthly_totals.json"


def _headers() -> dict:
    key = os.getenv("NVD_API_KEY") or os.getenv("NIST_API_KEY")
    return {"apiKey": key} if key else {}


def _count(session: requests.Session, start: str, end: str, headers: dict, severity: str | None = None) -> int:
    params = {"pubStartDate": start, "pubEndDate": end, "resultsPerPage": 1}
    if severity:
        params["cvssV3Severity"] = severity  # HIGH or CRITICAL
    r = session.get(URL, params=params, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json().get("totalResults", 0)


def _month_counts(session: requests.Session, year: int, month: int, headers: dict) -> dict:
    last_day = calendar.monthrange(year, month)[1]
    start = f"{year}-{month:02d}-01T00:00:00.000"
    end = f"{year}-{month:02d}-{last_day:02d}T23:59:59.999"
    total = _count(session, start, end, headers)
    high = _count(session, start, end, headers, "HIGH")
    crit = _count(session, start, end, headers, "CRITICAL")
    return {"total": total, "highCritical": high + crit}


def fetch(years: list[int]) -> dict:
    headers = _headers()
    session = requests.Session()
    now = datetime.now(timezone.utc)
    out: dict[str, dict] = {}
    for year in years:
        for month in range(1, 13):
            # Skip months entirely in the future.
            if year > now.year or (year == now.year and month > now.month):
                continue
            c = _month_counts(session, year, month, headers)
            out[f"{year}-{month:02d}"] = c
            print(f"  {year}-{month:02d}: total={c['total']} highCritical={c['highCritical']}")
    return out


def load_cache() -> dict:
    """Return the cache, normalizing legacy int values to the dict shape.

    Older caches stored a bare int per month; new ones store
    ``{"total": N, "highCritical": M}``. Callers can rely on the dict shape.
    """
    if not CACHE.exists():
        return {}
    try:
        raw = json.loads(CACHE.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    norm: dict[str, dict] = {}
    for k, v in raw.items():
        if isinstance(v, dict):
            norm[k] = v
        else:  # legacy bare int total
            norm[k] = {"total": v, "highCritical": None}
    return norm


if __name__ == "__main__":
    years = [int(a) for a in sys.argv[1:]] or [2025, 2026]
    print(f"Fetching NVD monthly publish counts (total + High/Critical) for {years} "
          f"({'keyed' if _headers() else 'anonymous'} rate tier)...")
    out = fetch(years)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {CACHE} ({len(out)} months)")
