"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

The KEV catalog is a single public JSON feed (no API key required):
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Docs: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from __future__ import annotations

import logging

import requests

from .http_client import build_session

logger = logging.getLogger(__name__)

KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class KevClient:
    """Client for the CISA KEV catalog JSON feed."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self.session = session or build_session()

    def fetch_catalog(self) -> dict:
        """Fetch and return the full KEV catalog as a dict.

        The payload includes metadata (``title``, ``catalogVersion``,
        ``dateReleased``, ``count``) plus a ``vulnerabilities`` list.
        """
        logger.info("Fetching CISA KEV catalog from %s", KEV_JSON_URL)
        resp = self.session.get(KEV_JSON_URL)
        resp.raise_for_status()
        catalog = resp.json()
        logger.info(
            "KEV catalog version=%s count=%s",
            catalog.get("catalogVersion"),
            catalog.get("count"),
        )
        return catalog

    def fetch_vulnerabilities(self) -> list[dict]:
        """Return just the list of KEV vulnerability records."""
        return self.fetch_catalog().get("vulnerabilities", [])
