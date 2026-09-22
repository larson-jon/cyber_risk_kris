"""SEC EDGAR full-text search client for 8-K cyber-incident disclosures.

Two disclosure paths are supported:

- **Item 1.05** -- the SEC's *mandatory* "material cybersecurity incident"
  disclosure (effective December 2023). Every 1.05 filing is cyber-related, so
  we simply keep filings whose structured ``items`` field contains ``1.05``.
- **Item 8.01** -- "Other Events", a catch-all used for *voluntary /
  non-material* disclosures of many kinds. Because 8.01 is not cyber-specific,
  we search for cyber-incident language (e.g. "cybersecurity incident",
  "data breach") and then keep only hits whose ``items`` include ``8.01``.

The client can also fetch each filing's document and extract the incident
narrative that follows the item heading.

API notes:
- Endpoint: https://efts.sec.gov/LATEST/search-index
- No API key. SEC requires a descriptive User-Agent identifying the requester.
- Fair-access limit: 10 requests/second. Exceeding it can get your IP blocked.
- Full-text coverage spans 2001-present. Item 1.05 only appears from Dec 2023.
- Pagination via ``from`` (offset).
"""

from __future__ import annotations

import html as html_module
import logging
import re
from typing import Iterator

import requests

from .http_client import RateLimiter, build_session

logger = logging.getLogger(__name__)

EDGAR_FTS_ENDPOINT = "https://efts.sec.gov/LATEST/search-index"
ARCHIVES_BASE = "https://www.sec.gov/Archives/edgar/data"

# Cyber-incident language used to narrow 8.01 (Other Events) filings, which are
# not cyber-specific. Phrases are OR-ed together in the full-text query.
CYBER_QUERY = (
    '"cybersecurity incident" OR "data breach" OR "unauthorized access" '
    'OR "ransomware" OR "cyberattack" OR "cyber-attack"'
)

# Terms that, if present in a filing's 8.01 *narrative* (not the whole
# document), confirm it is a genuine cyber-incident disclosure. Kept specific
# to avoid matching incidental words like "breach of covenant" in a contract.
CYBER_TERMS = (
    "cybersecurity",
    "cyber security",
    "cyber incident",
    "cyberattack",
    "cyber-attack",
    "cyber attack",
    "data breach",
    "data security incident",
    "ransomware",
    "unauthorized access",
    "unauthorized third party",
    "threat actor",
    "malware",
    "network security",
)

# The full-text search API returns a fixed page size of 10.
PAGE_SIZE = 10
# EDGAR full-text search only exposes up to 10,000 results per query.
MAX_RESULTS = 10_000

# Contact string sent to SEC per their fair-access policy. Override via the
# ``user_agent`` argument to identify your own organization/contact.
DEFAULT_USER_AGENT = "Cyber KRIs collector (contact: security@example.com)"


class EdgarClient:
    """Client for the SEC EDGAR full-text search API."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        session: requests.Session | None = None,
    ) -> None:
        self.session = session or build_session()
        # SEC keys rate limiting and access off the User-Agent; set it explicitly.
        self.session.headers["User-Agent"] = user_agent
        # Stay comfortably under the 10 req/s fair-access ceiling.
        self._limiter = RateLimiter(max_calls=8, period=1.0)

    def _search_page(self, query: str, forms: str, start: str, end: str, offset: int) -> dict:
        params = {
            "q": query,
            "forms": forms,
            "startdt": start,
            "enddt": end,
        }
        if offset:
            params["from"] = offset
        self._limiter.wait()
        logger.debug("EDGAR search params=%s", params)
        resp = self.session.get(EDGAR_FTS_ENDPOINT, params=params)
        resp.raise_for_status()
        return resp.json()

    def iter_search_hits(
        self,
        query: str,
        start_date: str,
        end_date: str,
        forms: str = "8-K",
    ) -> Iterator[dict]:
        """Yield raw search hits, transparently paging through all results."""
        offset = 0
        total: int | None = None
        while True:
            data = self._search_page(query, forms, start_date, end_date, offset)
            hits_meta = data.get("hits", {})
            total = hits_meta.get("total", {}).get("value", 0)
            page = hits_meta.get("hits", [])

            logger.info(
                "EDGAR page offset=%d returned=%d total=%s",
                offset,
                len(page),
                total,
            )
            if not page:
                break

            yield from page

            offset += len(page)
            if offset >= min(total or 0, MAX_RESULTS):
                break

    def iter_item_105_filings(
        self,
        start_date: str,
        end_date: str,
    ) -> Iterator[dict]:
        """Yield 8-K filings whose structured ``items`` include ``1.05``.

        We search for the phrase to narrow the candidate set server-side, then
        filter on the ``items`` field so we only keep genuine Item 1.05 filings
        (and drop ones that merely mention the phrase in prose).
        """
        for hit in self.iter_search_hits(
            query='"Item 1.05"', start_date=start_date, end_date=end_date, forms="8-K"
        ):
            source = hit.get("_source", {})
            if "1.05" in source.get("items", []):
                yield hit

    def iter_item_801_cyber_candidates(
        self,
        start_date: str,
        end_date: str,
    ) -> Iterator[dict]:
        """Yield candidate 8-K hits that carry Item 8.01 and cyber language.

        Item 8.01 ("Other Events") is a catch-all, so we search for cyber
        language to narrow the set, then keep only hits whose structured
        ``items`` include ``8.01`` (and not ``1.05``, which belongs to the
        material-incident collector). These are *candidates* only: the full-text
        match may be inside an attached exhibit, so callers should confirm the
        8.01 section of the primary document is genuinely cyber-related via
        :meth:`verify_and_describe_801`.
        """
        seen_accessions: set[str] = set()
        for hit in self.iter_search_hits(
            query=CYBER_QUERY, start_date=start_date, end_date=end_date, forms="8-K"
        ):
            source = hit.get("_source", {})
            items = source.get("items", [])
            if "8.01" not in items or "1.05" in items:
                continue
            # A filing can surface multiple times (one hit per matched doc);
            # only process each accession once.
            adsh = source.get("adsh", "")
            if adsh in seen_accessions:
                continue
            seen_accessions.add(adsh)
            yield hit

    def verify_and_describe_801(self, hit: dict, max_chars: int = 2000) -> str | None:
        """Confirm a candidate is a real 8.01 cyber disclosure and return its text.

        Fetches the primary 8-K document, extracts the Item 8.01 narrative, and
        returns it only if it contains cyber-incident language. Returns ``None``
        for false positives (cyber phrase was only in an exhibit).
        """
        _, text = self.fetch_primary_text(hit)
        if not text:
            return None
        narrative = extract_item_narrative_from_text(text, "8.01", max_chars=max_chars)
        if not narrative:
            return None
        # Require cyber language in the 8.01 narrative itself (not elsewhere in
        # the document), so we don't keep filings whose 8.01 is about something
        # else while a cyber word appears in an exhibit or unrelated section.
        low = narrative.lower()
        if any(term in low for term in CYBER_TERMS):
            return narrative
        return None

    def _get(self, url: str) -> requests.Response | None:
        self._limiter.wait()
        try:
            resp = self.session.get(url)
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            logger.warning("Could not fetch %s: %s", url, exc)
            return None

    def primary_document_url(self, hit: dict) -> str:
        """Resolve the URL of a filing's *primary* 8-K document.

        The full-text search matches individual documents, which are often
        attached exhibits rather than the 8-K body. We read the filing's
        ``index.json`` and pick the main ``*_8k.htm`` document (falling back to
        the largest .htm that isn't an exhibit), so narrative extraction reads
        the actual 8-K rather than an exhibit.
        """
        source = hit.get("_source", {})
        adsh = source.get("adsh", "")
        ciks = source.get("ciks", [])
        cik = ciks[0].lstrip("0") if ciks else ""
        acc_nodash = adsh.replace("-", "")
        if not (cik and acc_nodash):
            return ""

        index_url = f"{ARCHIVES_BASE}/{cik}/{acc_nodash}/index.json"
        resp = self._get(index_url)
        if not resp:
            return build_filing_url(hit)  # fall back to the matched document
        try:
            items = resp.json().get("directory", {}).get("item", [])
        except ValueError:
            return build_filing_url(hit)

        # Candidate documents: .htm/.html only, excluding EDGAR's own index,
        # header, and viewer files (which are not the filing body).
        htm = []
        for it in items:
            name = it.get("name", "")
            low = name.lower()
            if not low.endswith((".htm", ".html")):
                continue
            if "index" in low or "-index-headers" in low or low.startswith("r") and low[1:].split(".")[0].isdigit():
                continue  # skip index.html, *-index-headers.html, viewer Rn.htm
            htm.append(name)

        def is_exhibit(n: str) -> bool:
            low = n.lower()
            # Exhibit files: "exNN", "ex-NN", "exhibit", or the aNNN... naming
            # SEC uses for exhibits (a101..., a31..., a992...).
            return bool(
                re.search(r"ex[-_]?\d|exhibit", low)
                or re.match(r"a\d{2,}", low)
            )

        primary_doc = _get_primary_from_summary(self, cik, acc_nodash)
        if primary_doc:
            return f"{ARCHIVES_BASE}/{cik}/{acc_nodash}/{primary_doc}"

        # 1) Canonical primary 8-K doc (name ends in _8k.htm / -8k.htm).
        for name in htm:
            low = name.lower()
            if low.endswith("_8k.htm") or low.endswith("-8k.htm") or low.endswith("8k.htm"):
                return f"{ARCHIVES_BASE}/{cik}/{acc_nodash}/{name}"
        # 2) EDGAR's standard primary-doc naming: "<slug>-<8-digit date>.htm".
        for name in htm:
            if re.match(r".+-\d{8}\.htm$", name.lower()):
                return f"{ARCHIVES_BASE}/{cik}/{acc_nodash}/{name}"
        # 3) First non-exhibit document.
        for name in htm:
            if not is_exhibit(name):
                return f"{ARCHIVES_BASE}/{cik}/{acc_nodash}/{name}"
        # 4) Last resort: whatever the search matched.
        return build_filing_url(hit)

    def fetch_primary_text(self, hit: dict) -> tuple[str, str]:
        """Return ``(primary_doc_url, plain_text)`` for a filing's 8-K body."""
        url = self.primary_document_url(hit)
        if not url:
            return "", ""
        resp = self._get(url)
        if not resp:
            return url, ""
        return url, _html_to_text(resp.text)

    def fetch_incident_description(
        self, hit: dict, item: str, max_chars: int = 2000
    ) -> str:
        """Extract the narrative after an item heading in the primary 8-K doc."""
        _, text = self.fetch_primary_text(hit)
        if not text:
            return ""
        return extract_item_narrative_from_text(text, item, max_chars=max_chars)


def build_filing_url(hit: dict) -> str:
    """Construct the direct URL to a filing document from a search hit."""
    source = hit.get("_source", {})
    adsh = source.get("adsh", "")
    ciks = source.get("ciks", [])
    cik = ciks[0].lstrip("0") if ciks else ""
    # The hit _id is "<accession>:<document filename>".
    doc = hit.get("_id", "").split(":", 1)
    filename = doc[1] if len(doc) == 2 else ""
    acc_nodash = adsh.replace("-", "")
    if not (cik and acc_nodash and filename):
        return ""
    return f"{ARCHIVES_BASE}/{cik}/{acc_nodash}/{filename}"


def _get_primary_from_summary(client, cik: str, acc_nodash: str) -> str:
    """Return the primary document filename from a filing's header, or "".

    The ``<accession>-index-headers.html`` header lists documents in order; the
    first ``.htm`` with ``<TYPE>8-K`` is the primary 8-K body. This is more
    reliable than guessing from filenames.
    """
    header_url = (
        f"{ARCHIVES_BASE}/{cik}/{acc_nodash}/{_dash_accession(acc_nodash)}"
        "-index-headers.html"
    )
    resp = client._get(header_url)
    if not resp:
        return ""
    # The header lists <FILENAME> / <TYPE> pairs. Pick the .htm whose TYPE is 8-K.
    blocks = re.findall(
        r"<TYPE>([^<\r\n]+).*?<FILENAME>([^<\r\n]+)",
        resp.text,
        re.IGNORECASE | re.DOTALL,
    )
    for doc_type, filename in blocks:
        if doc_type.strip().upper().startswith("8-K") and filename.lower().endswith(
            (".htm", ".html")
        ):
            return filename.strip()
    return ""


def _dash_accession(acc_nodash: str) -> str:
    """Convert '000...118' back to dashed '0001749723-26-000118' form."""
    if len(acc_nodash) == 18:
        return f"{acc_nodash[:10]}-{acc_nodash[10:12]}-{acc_nodash[12:]}"
    return acc_nodash


def _html_to_text(html: str) -> str:
    """Strip an SEC filing's HTML down to normalized plain text."""
    text = re.sub(r"(?is)<script.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html_module.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


# Matches an item heading like "Item 8.01" or "Item 1.05" (dot may be escaped).
_ITEM_HEADING = r"Item\s+{item}\b"
# Any subsequent item heading or the signature block marks the end of a section.
_NEXT_SECTION = re.compile(
    r"Item\s+\d\.\d{2}\b|SIGNATURES?\b|Pursuant to the requirements",
    re.IGNORECASE,
)


def extract_item_narrative(html: str, item: str, max_chars: int = 2000) -> str:
    """Extract the ``Item <item>`` narrative from a filing's raw HTML."""
    return extract_item_narrative_from_text(
        _html_to_text(html), item, max_chars=max_chars
    )


def extract_item_narrative_from_text(text: str, item: str, max_chars: int = 2000) -> str:
    """Extract the text that follows an ``Item <item>`` heading in plain text.

    The excerpt runs from just after the item heading to the next item heading
    or signature block, trimmed to ``max_chars``.
    """
    heading = re.compile(_ITEM_HEADING.format(item=re.escape(item)), re.IGNORECASE)
    match = heading.search(text)
    if not match:
        return ""

    start = match.end()
    rest = text[start:].lstrip(" .:-")
    # Drop the standard item title (e.g. "Material Cybersecurity Incidents.",
    # "Other Events.") so the excerpt begins with the actual narrative.
    rest = re.sub(
        r"^(Material Cybersecurity Incidents?|Other Events?)\.?\s*",
        "",
        rest,
        flags=re.IGNORECASE,
    )

    # Find the next section boundary within the remaining text.
    nxt = _NEXT_SECTION.search(rest)
    section = rest[: nxt.start()] if nxt else rest
    section = section.strip()
    if len(section) > max_chars:
        section = section[:max_chars].rstrip() + "..."
    return section
