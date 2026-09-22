"""Fetch and cache the total number of CVEs NVD *published* per month.

The KEV enrichment only ever pulls the ~1,700 exploited CVEs, so it can't tell
you the denominator: how many CVEs were published overall. This script queries
the NVD API's ``pubStartDate`` / ``pubEndDate`` for each month and caches the
monthly ``totalResults`` to data/nvd_monthly_totals.json.

The KEV EDA report reads that cache to plot total published CVEs (secondary
axis) against the tiny exploited (KEV) counts -- the "how few get exploited"
context.

Usage:  python analysis/nvd_monthly_totals.py 2025 2026
Output: data/nvd_monthly_totals.json  ({"2025-01": 12345, ...})
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


def _month_total(session: requests.Session, year: int, month: int, headers: dict) -> int:
    last_day = calendar.monthrange(year, month)[1]
    start = f"{year}-{month:02d}-01T00:00:00.000"
    end = f"{year}-{month:02d}-{last_day:02d}T23:59:59.999"
    params = {"pubStartDate": start, "pubEndDate": end, "resultsPerPage": 1}
    r = session.get(URL, params=params, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json().get("totalResults", 0)


def fetch(years: list[int]) -> dict:
    headers = _headers()
    session = requests.Session()
    now = datetime.now(timezone.utc)
    totals: dict[str, int] = {}
    for year in years:
        for month in range(1, 13):
            # Skip months entirely in the future.
            if year > now.year or (year == now.year and month > now.month):
                continue
            n = _month_total(session, year, month, headers)
            totals[f"{year}-{month:02d}"] = n
            print(f"  {year}-{month:02d}: {n}")
    return totals


def load_cache() -> dict:
    if CACHE.exists():
        try:
            return json.loads(CACHE.read_text(encoding="utf-8"))
        except ValueError:
            return {}
    return {}


if __name__ == "__main__":
    years = [int(a) for a in sys.argv[1:]] or [2025, 2026]
    print(f"Fetching NVD monthly publish totals for {years} "
          f"({'keyed' if _headers() else 'anonymous'} rate tier)...")
    totals = fetch(years)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(totals, indent=2), encoding="utf-8")
    print(f"\nWrote {CACHE} ({len(totals)} months)")
