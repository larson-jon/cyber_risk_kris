"""NIST National Vulnerability Database (NVD) API 2.0 client.

Docs: https://nvd.nist.gov/developers/vulnerabilities

Notes on the API that drive this implementation:
- Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
- Offset-based pagination via ``startIndex`` and ``resultsPerPage``
  (max 2000 results per page).
- Incremental pulls use ``lastModStartDate`` / ``lastModEndDate``; the maximum
  range for any date filter is 120 consecutive days.
- Rate limits: 5 requests / 30s without an API key, 50 / 30s with one. The key
  is passed in the ``apiKey`` request header.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Iterator

import requests

from .http_client import RateLimiter, build_session

logger = logging.getLogger(__name__)

NVD_CVES_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# API-enforced ceilings.
MAX_RESULTS_PER_PAGE = 2000
MAX_DATE_RANGE_DAYS = 120

# NVD expects extended ISO-8601 with milliseconds, e.g. 2024-01-01T00:00:00.000
NVD_DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"


def _format_nvd_datetime(dt: datetime) -> str:
    """Format a datetime the way the NVD API expects (millisecond precision)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    # strftime %f gives microseconds; trim to milliseconds.
    return dt.strftime(NVD_DATETIME_FORMAT)[:-3]


class NvdClient:
    """Client for the NVD CVE API 2.0."""

    def __init__(
        self,
        api_key: str | None = None,
        results_per_page: int = MAX_RESULTS_PER_PAGE,
        session: requests.Session | None = None,
    ) -> None:
        self.api_key = api_key
        self.results_per_page = min(results_per_page, MAX_RESULTS_PER_PAGE)
        self.session = session or build_session()

        if api_key:
            self.session.headers["apiKey"] = api_key

        # Public rate limits are 5/30s (no key) and 50/30s (with key). We stay a
        # little under the ceiling to avoid tripping NIST's firewall rules.
        if api_key:
            self._limiter = RateLimiter(max_calls=45, period=30.0)
        else:
            self._limiter = RateLimiter(max_calls=4, period=30.0)

    def _get_page(self, params: dict) -> dict:
        self._limiter.wait()
        logger.debug("GET %s params=%s", NVD_CVES_ENDPOINT, params)
        resp = self.session.get(NVD_CVES_ENDPOINT, params=params)
        resp.raise_for_status()
        return resp.json()

    def get_cve(self, cve_id: str) -> dict | None:
        """Fetch a single CVE by its ID (e.g. ``CVE-2021-44228``).

        Returns the raw ``vulnerabilities`` entry (with a top-level ``cve`` key)
        or ``None`` if the ID is not found in NVD.
        """
        data = self._get_page({"cveId": cve_id})
        vulnerabilities = data.get("vulnerabilities", [])
        return vulnerabilities[0] if vulnerabilities else None

    def iter_cves(
        self,
        last_mod_start: datetime | None = None,
        last_mod_end: datetime | None = None,
        extra_params: dict | None = None,
    ) -> Iterator[dict]:
        """Yield individual CVE records, transparently handling pagination.

        If ``last_mod_start``/``last_mod_end`` are given, only CVEs modified in
        that window are returned. The window must not exceed 120 days; use
        :meth:`iter_cves_windowed` for larger backfills.
        """
        params: dict = {"resultsPerPage": self.results_per_page, "startIndex": 0}
        if extra_params:
            params.update(extra_params)

        if last_mod_start and last_mod_end:
            _validate_date_range(last_mod_start, last_mod_end)
            params["lastModStartDate"] = _format_nvd_datetime(last_mod_start)
            params["lastModEndDate"] = _format_nvd_datetime(last_mod_end)

        start_index = 0
        total_results: int | None = None

        while True:
            params["startIndex"] = start_index
            data = self._get_page(params)

            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            page_size = data.get("resultsPerPage", len(vulnerabilities))

            logger.info(
                "NVD page startIndex=%d returned=%d total=%s",
                start_index,
                len(vulnerabilities),
                total_results,
            )

            yield from vulnerabilities

            start_index += page_size if page_size else len(vulnerabilities)
            if not vulnerabilities or start_index >= (total_results or 0):
                break

    def iter_cves_windowed(
        self,
        last_mod_start: datetime,
        last_mod_end: datetime,
        window_days: int = MAX_DATE_RANGE_DAYS,
    ) -> Iterator[dict]:
        """Backfill across ranges larger than 120 days by chunking the window."""
        window_days = min(window_days, MAX_DATE_RANGE_DAYS)
        cursor = last_mod_start
        while cursor < last_mod_end:
            chunk_end = min(cursor + timedelta(days=window_days), last_mod_end)
            logger.info("NVD window %s -> %s", cursor.date(), chunk_end.date())
            yield from self.iter_cves(
                last_mod_start=cursor, last_mod_end=chunk_end
            )
            cursor = chunk_end


def _validate_date_range(start: datetime, end: datetime) -> None:
    if end < start:
        raise ValueError("last_mod_end must be on or after last_mod_start")
    if (end - start) > timedelta(days=MAX_DATE_RANGE_DAYS):
        raise ValueError(
            f"NVD date range cannot exceed {MAX_DATE_RANGE_DAYS} days; "
            "use iter_cves_windowed() for larger backfills"
        )
