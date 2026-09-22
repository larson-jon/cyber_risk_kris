"""Flatten nested NVD / KEV records into flat rows suitable for CSV output.

Each function returns a list of dicts (rows) with a stable set of columns so the
CSV header is consistent regardless of which optional fields a record contains.
"""

from __future__ import annotations

# Preference order for CVSS metrics: newest / richest first.
_CVSS_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

NVD_COLUMNS = [
    "cve_id",
    "source_identifier",
    "published",
    "last_modified",
    "vuln_status",
    "description",
    "cvss_version",
    "cvss_base_score",
    "cvss_base_severity",
    "cvss_vector",
    "cvss_source",
    "cwes",
    "reference_urls",
]

KEV_COLUMNS = [
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "short_description",
    "required_action",
    "due_date",
    "known_ransomware_campaign_use",
    "cwes",
    "notes",
]


def _english_description(descriptions: list[dict]) -> str:
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    # Fall back to the first description if no English entry exists.
    return descriptions[0].get("value", "") if descriptions else ""


def _select_cvss(metrics: dict) -> dict:
    """Return a flat dict of CVSS fields from the best available metric."""
    empty = {
        "cvss_version": "",
        "cvss_base_score": "",
        "cvss_base_severity": "",
        "cvss_vector": "",
        "cvss_source": "",
    }
    for key in _CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not entries:
            continue
        entry = entries[0]
        data = entry.get("cvssData", {})
        # CVSS v2 carries baseSeverity on the metric entry, not in cvssData.
        severity = data.get("baseSeverity") or entry.get("baseSeverity", "")
        return {
            "cvss_version": data.get("version", ""),
            "cvss_base_score": data.get("baseScore", ""),
            "cvss_base_severity": severity,
            "cvss_vector": data.get("vectorString", ""),
            "cvss_source": entry.get("source", ""),
        }
    return empty


def _cwes_from_weaknesses(weaknesses: list[dict]) -> str:
    cwes: list[str] = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value and value not in cwes:
                cwes.append(value)
    return "; ".join(cwes)


def flatten_nvd(vulnerabilities: list[dict]) -> list[dict]:
    """Flatten NVD API 2.0 ``vulnerabilities`` entries into CSV rows."""
    rows: list[dict] = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        cvss = _select_cvss(cve.get("metrics", {}))
        references = cve.get("references", [])
        ref_urls = "; ".join(
            ref.get("url", "") for ref in references if ref.get("url")
        )
        row = {
            "cve_id": cve.get("id", ""),
            "source_identifier": cve.get("sourceIdentifier", ""),
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "vuln_status": cve.get("vulnStatus", ""),
            "description": _english_description(cve.get("descriptions", [])),
            "cwes": _cwes_from_weaknesses(cve.get("weaknesses", [])),
            "reference_urls": ref_urls,
        }
        row.update(cvss)
        rows.append(row)
    return rows


def flatten_kev(vulnerabilities: list[dict]) -> list[dict]:
    """Flatten CISA KEV ``vulnerabilities`` entries into CSV rows."""
    rows: list[dict] = []
    for item in vulnerabilities:
        rows.append(_kev_row(item))
    return rows


def _kev_row(item: dict) -> dict:
    return {
        "cve_id": item.get("cveID", ""),
        "vendor_project": item.get("vendorProject", ""),
        "product": item.get("product", ""),
        "vulnerability_name": item.get("vulnerabilityName", ""),
        "date_added": item.get("dateAdded", ""),
        "short_description": item.get("shortDescription", ""),
        "required_action": item.get("requiredAction", ""),
        "due_date": item.get("dueDate", ""),
        "known_ransomware_campaign_use": item.get(
            "knownRansomwareCampaignUse", ""
        ),
        "cwes": "; ".join(item.get("cwes", []) or []),
        "notes": item.get("notes", ""),
    }


# ---------------------------------------------------------------------------
# Combined KEV + NVD enrichment
# ---------------------------------------------------------------------------

# KEV-derived columns first (exploitation context), then NVD detail. The
# ``nvd_`` prefix on shared concepts (cwes, published) avoids clashing with the
# KEV values so you can compare them side by side.
ENRICHED_COLUMNS = [
    # KEV (exploitation context)
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "due_date",
    "known_ransomware_campaign_use",
    "kev_cwes",
    "short_description",
    # NVD (severity / classification)
    "in_nvd",
    "nvd_published",
    "nvd_last_modified",
    "nvd_vuln_status",
    "cvss_version",
    "cvss_base_score",
    "cvss_base_severity",
    "cvss_vector",
    "cvss_source",
    "nvd_cwes",
    "nvd_affected_products",
    "nvd_description",
]


def _affected_products(cve: dict, limit: int = 25) -> str:
    """Return a de-duplicated ``vendor:product`` list from NVD configurations."""
    products: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                # CPE 2.3: cpe:2.3:<part>:<vendor>:<product>:<version>:...
                parts = match.get("criteria", "").split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    label = f"{vendor}:{product}"
                    if label not in products:
                        products.append(label)
    if len(products) > limit:
        return "; ".join(products[:limit]) + f"; (+{len(products) - limit} more)"
    return "; ".join(products)


def flatten_enriched(
    kev_vulnerabilities: list[dict],
    nvd_by_id: dict[str, dict],
) -> list[dict]:
    """Join KEV records with their NVD detail into a single row per CVE.

    ``nvd_by_id`` maps a CVE ID to its raw NVD ``vulnerabilities`` entry (the
    object with a top-level ``cve`` key), or is missing that ID entirely if NVD
    had no record for it.
    """
    rows: list[dict] = []
    for item in kev_vulnerabilities:
        kev = _kev_row(item)
        cve_id = kev["cve_id"]

        row: dict = {
            "cve_id": cve_id,
            "vendor_project": kev["vendor_project"],
            "product": kev["product"],
            "vulnerability_name": kev["vulnerability_name"],
            "date_added": kev["date_added"],
            "due_date": kev["due_date"],
            "known_ransomware_campaign_use": kev["known_ransomware_campaign_use"],
            "kev_cwes": kev["cwes"],
            "short_description": kev["short_description"],
            # NVD defaults (filled below if present).
            "in_nvd": False,
            "nvd_published": "",
            "nvd_last_modified": "",
            "nvd_vuln_status": "",
            "cvss_version": "",
            "cvss_base_score": "",
            "cvss_base_severity": "",
            "cvss_vector": "",
            "cvss_source": "",
            "nvd_cwes": "",
            "nvd_affected_products": "",
            "nvd_description": "",
        }

        nvd_entry = nvd_by_id.get(cve_id)
        if nvd_entry:
            cve = nvd_entry.get("cve", {})
            cvss = _select_cvss(cve.get("metrics", {}))
            row.update(
                {
                    "in_nvd": True,
                    "nvd_published": cve.get("published", ""),
                    "nvd_last_modified": cve.get("lastModified", ""),
                    "nvd_vuln_status": cve.get("vulnStatus", ""),
                    "nvd_cwes": _cwes_from_weaknesses(cve.get("weaknesses", [])),
                    "nvd_affected_products": _affected_products(cve),
                    "nvd_description": _english_description(
                        cve.get("descriptions", [])
                    ),
                    **cvss,
                }
            )
        rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# SEC EDGAR 8-K cyber-incident filings (Item 1.05 and Item 8.01)
# ---------------------------------------------------------------------------

EDGAR_COLUMNS = [
    "disclosure_type",
    "accession",
    "company",
    "ticker",
    "cik",
    "form",
    "filing_date",
    "period_ending",
    "items",
    "business_location",
    "sic_code",
    "industry",
    "incident_type",
    "third_party",
    "data_types",
    "status",
    "themes",
    "incident_description",
    "filing_url",
]


# SIC major-group prefixes -> broad industry label. SIC is a 4-digit code; the
# leading digits map to divisions/major groups. This is a pragmatic grouping,
# not the full 400+ code table.
def sic_to_industry(sic: str) -> str:
    if not sic or not sic.isdigit():
        return "Unknown"
    code = int(sic)
    ranges = [
        (100, 999, "Agriculture / Forestry / Fishing"),
        (1000, 1499, "Mining"),
        (1500, 1799, "Construction"),
        (2000, 2199, "Food & Beverage Mfg"),
        (2200, 2399, "Textiles & Apparel Mfg"),
        (2400, 2799, "Wood / Paper / Printing Mfg"),
        (2800, 2899, "Chemicals & Pharma Mfg"),
        (2900, 3099, "Petroleum / Rubber / Plastics Mfg"),
        (3100, 3399, "Metals & Materials Mfg"),
        (3400, 3599, "Industrial Machinery Mfg"),
        (3600, 3699, "Electronics & Electrical Mfg"),
        (3700, 3799, "Transportation Equipment Mfg"),
        (3800, 3899, "Instruments & Medical Devices Mfg"),
        (3900, 3999, "Misc Manufacturing"),
        (4000, 4799, "Transportation & Logistics"),
        (4800, 4899, "Communications / Telecom"),
        (4900, 4999, "Utilities & Energy"),
        (5000, 5199, "Wholesale Trade"),
        (5200, 5999, "Retail Trade"),
        (6000, 6199, "Banking & Credit"),
        (6200, 6299, "Securities & Investments"),
        (6300, 6499, "Insurance"),
        (6500, 6599, "Real Estate"),
        (6700, 6799, "Holding & Investment Offices"),
        (7000, 7299, "Consumer Services"),
        (7300, 7399, "Business & IT Services"),
        (7370, 7379, "Computer / Software Services"),
        (7400, 7999, "Services (Misc)"),
        (8000, 8099, "Health Services"),
        (8200, 8299, "Educational Services"),
        (8700, 8799, "Engineering / Research / Consulting"),
    ]
    for lo, hi, label in ranges:
        if lo <= code <= hi:
            return label
    return f"Other (SIC {sic})"


# --- Narrative theme tagging (deterministic keyword patterns) ---------------
import re as _re

_THEME_PATTERNS = {
    "ransomware": r"ransom",
    "data_exfiltration": r"exfiltrat|data (?:was |were )?(?:stolen|acquired|obtained|copied|taken)|obtained .{0,25}data",
    "unauthorized_access": r"unauthoriz(?:ed|ed party|ed actor|ed access|ed third)",
    "operational_disruption": r"disrupt|outage|offline|shut ?down|unavailable|network outage|took .{0,15}systems? offline",
    "third_party_vendor": r"third[- ]party|vendor|supplier|supply chain|service provider",
    "phishing_credentials": r"phishing|stolen credential|credential|compromised account",
    "personal_data": r"personal (?:information|data)|personally identifiable|\bPII\b",
    "health_data": r"protected health|\bPHI\b|health information",
    "financial_data": r"financial (?:information|account|data)|payment card|bank account",
    "litigation": r"lawsuit|class action|litigation|complaint|plaintiff",
    "law_enforcement": r"law enforcement|\bFBI\b|federal authorities",
    "insurance": r"cyber ?insurance|insurance (?:coverage|policy|carrier)",
}

_INCIDENT_TYPE_ORDER = [
    ("Ransomware", r"ransom"),
    ("Vendor / supply-chain", r"third[- ]party (?:vendor|service|provider)|vendor(?:'s)? (?:environment|systems|incident)|supply chain"),
    ("Data theft", r"exfiltrat|data (?:was |were )?(?:stolen|acquired|obtained|copied)|obtained .{0,25}data set"),
    ("Operational disruption", r"disrupt|outage|offline|shut ?down|network outage"),
    ("Unauthorized access", r"unauthoriz"),
]


def _tag_narrative(text: str) -> dict:
    """Derive incident_type, third_party flag, data_types, status, themes."""
    low = (text or "").lower()
    themes = [name for name, pat in _THEME_PATTERNS.items() if _re.search(pat, low)]

    # Primary incident type: first matching category in priority order.
    incident_type = "Unspecified"
    for label, pat in _INCIDENT_TYPE_ORDER:
        if _re.search(pat, low):
            incident_type = label
            break

    third_party = bool(_re.search(_THEME_PATTERNS["third_party_vendor"], low))

    data_types = []
    if _re.search(_THEME_PATTERNS["health_data"], low):
        data_types.append("PHI")
    if _re.search(_THEME_PATTERNS["personal_data"], low):
        data_types.append("PII")
    if _re.search(_THEME_PATTERNS["financial_data"], low):
        data_types.append("Financial")

    # Status: litigation > contained/restored > investigating > not-material.
    if _re.search(_THEME_PATTERNS["litigation"], low):
        status = "Litigation"
    elif _re.search(r"restored|contained|resolved|remediat", low):
        status = "Contained / restored"
    elif _re.search(r"ongoing|continues? to (?:investigate|assess)|preliminary|investigation", low):
        status = "Investigating"
    elif _re.search(r"not .{0,30}material|no .{0,20}material (?:adverse )?(?:effect|impact)", low):
        status = "Deemed not material"
    else:
        status = "Reported"

    return {
        "incident_type": incident_type,
        "third_party": "Yes" if third_party else "No",
        "data_types": "; ".join(data_types),
        "status": status,
        "themes": "; ".join(themes),
    }


def _parse_display_name(display_name: str) -> tuple[str, str]:
    """Split an EDGAR display name into (company, ticker).

    Display names look like ``"AMGEN INC  (AMGN)  (CIK 0000318154)"``.
    """
    company = display_name
    ticker = ""
    # The ticker is the first parenthetical that is not the CIK.
    if "(" in display_name:
        company = display_name.split("(", 1)[0].strip()
        for chunk in display_name.split("(")[1:]:
            token = chunk.split(")", 1)[0].strip()
            if token and not token.upper().startswith("CIK"):
                ticker = token
                break
    return company, ticker


def flatten_edgar(
    hits: list[dict],
    disclosure_type: str = "",
    descriptions: dict[str, str] | None = None,
) -> list[dict]:
    """Flatten EDGAR full-text search hits into CSV rows.

    ``disclosure_type`` labels the rows (e.g. ``"1.05"`` or ``"8.01"``).
    ``descriptions`` optionally maps a hit ``_id`` to its extracted incident
    narrative; hits without an entry get an empty description.

    Importing ``build_filing_url`` here (rather than at module top) avoids a
    circular import, since ``edgar`` imports the shared HTTP client.
    """
    from .edgar import build_filing_url

    descriptions = descriptions or {}
    rows: list[dict] = []
    for hit in hits:
        source = hit.get("_source", {})
        display_names = source.get("display_names", [])
        company, ticker = (
            _parse_display_name(display_names[0]) if display_names else ("", "")
        )
        ciks = source.get("ciks", [])
        biz = source.get("biz_locations", [])
        sics = source.get("sics", [])
        sic_code = sics[0] if sics else ""
        description = descriptions.get(hit.get("_id", ""), "")
        tags = _tag_narrative(description)
        rows.append(
            {
                "disclosure_type": disclosure_type,
                "accession": source.get("adsh", ""),
                "company": company,
                "ticker": ticker,
                "cik": ciks[0] if ciks else "",
                "form": source.get("form", ""),
                "filing_date": source.get("file_date", ""),
                "period_ending": source.get("period_ending", ""),
                "items": "; ".join(source.get("items", []) or []),
                "business_location": biz[0] if biz else "",
                "sic_code": sic_code,
                "industry": sic_to_industry(sic_code),
                "incident_type": tags["incident_type"],
                "third_party": tags["third_party"],
                "data_types": tags["data_types"],
                "status": tags["status"],
                "themes": tags["themes"],
                "incident_description": description,
                "filing_url": build_filing_url(hit),
            }
        )
    return rows
