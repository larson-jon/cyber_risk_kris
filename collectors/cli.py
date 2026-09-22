"""Command-line entry point for the cyber security data collectors.

Examples
--------
Pull the full CISA KEV catalog:

    python -m collectors.cli kev

Pull CVEs modified in the last 7 days from NVD:

    python -m collectors.cli nvd --last-days 7

Backfill CVEs modified within an explicit date range:

    python -m collectors.cli nvd --start 2024-01-01 --end 2024-06-01

Pull everything (NVD last-N-days + full KEV):

    python -m collectors.cli all --last-days 7
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import Config
from .edgar import EdgarClient
from .flatten import (
    EDGAR_COLUMNS,
    ENRICHED_COLUMNS,
    KEV_COLUMNS,
    NVD_COLUMNS,
    flatten_edgar,
    flatten_enriched,
    flatten_kev,
    flatten_nvd,
)
from .kev import KevClient
from .nvd import NvdClient

logger = logging.getLogger("collectors")


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _write_json(data, out_dir: Path, name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}_{_timestamp()}.json"
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    logger.info("Wrote %s", path)
    return path


def _write_csv(rows: list[dict], columns: list[str], out_dir: Path, name: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}_{_timestamp()}.csv"
    # newline="" per the csv module docs to avoid blank rows on Windows.
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    logger.info("Wrote %s (%d rows)", path, len(rows))
    return path


def _parse_date(value: str) -> datetime:
    """Parse YYYY-MM-DD or full ISO-8601 into an aware UTC datetime."""
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid date '{value}'. Use YYYY-MM-DD or ISO-8601."
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def run_kev(config: Config, fmt: str = "csv") -> list[Path]:
    client = KevClient()
    catalog = client.fetch_catalog()
    vulns = catalog.get("vulnerabilities", [])
    logger.info("Collected %d KEV records", len(vulns))

    outputs: list[Path] = []
    if fmt in ("json", "both"):
        outputs.append(_write_json(catalog, config.data_dir, "cisa_kev"))
    if fmt in ("csv", "both"):
        rows = flatten_kev(vulns)
        outputs.append(_write_csv(rows, KEV_COLUMNS, config.data_dir, "cisa_kev"))
    return outputs


def run_nvd(config: Config, args: argparse.Namespace) -> list[Path]:
    client = NvdClient(api_key=config.nvd_api_key)

    start: datetime | None = None
    end: datetime | None = None

    if args.last_days is not None:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=args.last_days)
    elif args.start or args.end:
        if not (args.start and args.end):
            raise SystemExit("--start and --end must be provided together")
        start, end = args.start, args.end

    if start and end:
        records = list(client.iter_cves_windowed(start, end))
    else:
        # No date filter: pull the entire dataset (large; use with care).
        logger.warning(
            "No date range given; pulling the full NVD dataset. This is large."
        )
        records = list(client.iter_cves())

    logger.info("Collected %d CVE records", len(records))

    fmt = getattr(args, "format", "csv")
    outputs: list[Path] = []
    if fmt in ("json", "both"):
        payload = {
            "source": "nvd-cve-api-2.0",
            "collectedAt": datetime.now(timezone.utc).isoformat(),
            "range": {
                "start": start.isoformat() if start else None,
                "end": end.isoformat() if end else None,
            },
            "count": len(records),
            "vulnerabilities": records,
        }
        outputs.append(_write_json(payload, config.data_dir, "nvd_cves"))
    if fmt in ("csv", "both"):
        rows = flatten_nvd(records)
        outputs.append(_write_csv(rows, NVD_COLUMNS, config.data_dir, "nvd_cves"))
    return outputs


def run_enrich(config: Config, fmt: str = "csv") -> list[Path]:
    """Fetch KEV, look up each KEV CVE in NVD by ID, write the joined dataset."""
    kev_client = KevClient()
    kev_vulns = kev_client.fetch_vulnerabilities()
    logger.info("Fetched %d KEV records", len(kev_vulns))

    nvd_client = NvdClient(api_key=config.nvd_api_key)
    if not config.nvd_api_key:
        logger.warning(
            "No NVD API key found; enrichment will be slow (5 requests / 30s). "
            "Set NVD_API_KEY in .env for the 50/30s tier."
        )

    cve_ids = [v.get("cveID", "") for v in kev_vulns if v.get("cveID")]
    total = len(cve_ids)
    nvd_by_id: dict[str, dict] = {}
    missing: list[str] = []

    for idx, cve_id in enumerate(cve_ids, start=1):
        try:
            entry = nvd_client.get_cve(cve_id)
        except Exception as exc:  # network / HTTP errors after retries
            logger.error("Lookup failed for %s: %s", cve_id, exc)
            missing.append(cve_id)
            continue
        if entry:
            nvd_by_id[cve_id] = entry
        else:
            missing.append(cve_id)
        if idx % 50 == 0 or idx == total:
            logger.info("Enriched %d/%d CVEs", idx, total)

    logger.info(
        "NVD detail found for %d/%d KEV CVEs (%d missing)",
        len(nvd_by_id),
        total,
        len(missing),
    )
    if missing:
        logger.info("CVEs without NVD detail: %s", ", ".join(missing[:20]))

    rows = flatten_enriched(kev_vulns, nvd_by_id)

    outputs: list[Path] = []
    if fmt in ("csv", "both"):
        outputs.append(
            _write_csv(rows, ENRICHED_COLUMNS, config.data_dir, "kev_enriched")
        )
    if fmt in ("json", "both"):
        payload = {
            "source": "kev+nvd-enriched",
            "collectedAt": datetime.now(timezone.utc).isoformat(),
            "kevCount": total,
            "nvdMatched": len(nvd_by_id),
            "records": rows,
        }
        outputs.append(_write_json(payload, config.data_dir, "kev_enriched"))
    return outputs


# Default search window start. The Item 1.05 rule took effect Dec 2023, but we
# default to 2026-01-01 per project scope; override with --start to go earlier.
EDGAR_DEFAULT_START = "2026-01-01"


def _collect_105(client: EdgarClient, start: str, end: str, with_descriptions: bool) -> list[dict]:
    """Every Item 1.05 filing is a material cyber incident; keep them all."""
    hits = list(client.iter_item_105_filings(start_date=start, end_date=end))
    logger.info("Found %d Item 1.05 filings", len(hits))
    descriptions: dict[str, str] = {}
    if with_descriptions and hits:
        logger.info("Fetching incident descriptions for %d filings...", len(hits))
        for idx, hit in enumerate(hits, start=1):
            descriptions[hit.get("_id", "")] = client.fetch_incident_description(
                hit, "1.05"
            )
            if idx % 25 == 0 or idx == len(hits):
                logger.info("  fetched %d/%d descriptions", idx, len(hits))
    return flatten_edgar(hits, disclosure_type="1.05", descriptions=descriptions)


def _collect_801(client: EdgarClient, start: str, end: str) -> list[dict]:
    """Item 8.01 is a catch-all, so verify each candidate is truly cyber.

    We must fetch the primary document to filter false positives, so the
    incident description is always produced here (no cheap metadata-only mode).
    """
    candidates = list(
        client.iter_item_801_cyber_candidates(start_date=start, end_date=end)
    )
    logger.info(
        "Found %d candidate Item 8.01 filings; verifying each is cyber-related...",
        len(candidates),
    )
    kept_hits: list[dict] = []
    descriptions: dict[str, str] = {}
    for idx, hit in enumerate(candidates, start=1):
        narrative = client.verify_and_describe_801(hit)
        if narrative is not None:
            kept_hits.append(hit)
            descriptions[hit.get("_id", "")] = narrative
        if idx % 25 == 0 or idx == len(candidates):
            logger.info("  verified %d/%d (kept %d)", idx, len(candidates), len(kept_hits))
    logger.info(
        "Kept %d genuine Item 8.01 cyber filings (dropped %d false positives)",
        len(kept_hits),
        len(candidates) - len(kept_hits),
    )
    return flatten_edgar(kept_hits, disclosure_type="8.01", descriptions=descriptions)


def _collect_edgar_item(
    client: EdgarClient,
    item: str,
    start: str,
    end: str,
    with_descriptions: bool,
) -> list[dict]:
    """Search one item type, return flat rows."""
    if item == "1.05":
        return _collect_105(client, start, end, with_descriptions)
    if item == "8.01":
        return _collect_801(client, start, end)
    raise ValueError(f"Unknown EDGAR item: {item}")


def run_edgar(config: Config, args: argparse.Namespace) -> list[Path]:
    """Collect 8-K cyber-incident filings (Item 1.05 and/or 8.01) from EDGAR."""
    start = args.start.date().isoformat() if args.start else EDGAR_DEFAULT_START
    end = (
        args.end.date().isoformat()
        if args.end
        else datetime.now(timezone.utc).date().isoformat()
    )

    if args.item == "both":
        items = ["1.05", "8.01"]
    else:
        items = [args.item]

    # Prefer an explicit --user-agent, else EDGAR_USER_AGENT env, else default.
    user_agent = args.user_agent or config.edgar_user_agent
    client = EdgarClient(user_agent=user_agent) if user_agent else EdgarClient()
    with_descriptions = not args.no_descriptions

    rows: list[dict] = []
    for item in items:
        logger.info("Searching EDGAR for 8-K Item %s filings %s -> %s", item, start, end)
        rows.extend(
            _collect_edgar_item(client, item, start, end, with_descriptions)
        )

    # Sort newest first for convenience.
    rows.sort(key=lambda r: r["filing_date"], reverse=True)

    name = "edgar_8k_cyber" if len(items) > 1 else f"edgar_8k_item{items[0].replace('.', '')}"
    fmt = getattr(args, "format", "csv")
    outputs: list[Path] = []
    if fmt in ("csv", "both"):
        outputs.append(_write_csv(rows, EDGAR_COLUMNS, config.data_dir, name))
    if fmt in ("json", "both"):
        payload = {
            "source": "sec-edgar-fts",
            "items": items,
            "collectedAt": datetime.now(timezone.utc).isoformat(),
            "range": {"start": start, "end": end},
            "count": len(rows),
            "filings": rows,
        }
        outputs.append(_write_json(payload, config.data_dir, name))
    return outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="collectors",
        description="Collect cyber security data from NIST NVD and CISA KEV.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug logging."
    )

    sub = parser.add_subparsers(dest="command", required=True)

    kev_p = sub.add_parser("kev", help="Fetch the full CISA KEV catalog.")
    _add_format_arg(kev_p)

    nvd_p = sub.add_parser("nvd", help="Fetch CVEs from the NVD API 2.0.")
    _add_nvd_args(nvd_p)
    _add_format_arg(nvd_p)

    all_p = sub.add_parser("all", help="Run both the NVD and KEV collectors.")
    _add_nvd_args(all_p)
    _add_format_arg(all_p)

    enrich_p = sub.add_parser(
        "enrich",
        help="Fetch KEV and enrich each CVE with NVD detail (joined on cve_id).",
    )
    _add_format_arg(enrich_p)

    edgar_p = sub.add_parser(
        "edgar",
        help="Collect SEC 8-K cyber-incident filings (Item 1.05 and/or 8.01).",
    )
    edgar_p.add_argument(
        "--item",
        choices=("1.05", "8.01", "both"),
        default="1.05",
        help="Which disclosure item to collect (default: 1.05).",
    )
    edgar_p.add_argument(
        "--no-descriptions",
        action="store_true",
        help="Skip fetching each filing's incident narrative (faster).",
    )
    edgar_p.add_argument(
        "--start",
        type=_parse_date,
        default=None,
        help="Start filing date (YYYY-MM-DD). Default: 2026-01-01 (both items).",
    )
    edgar_p.add_argument(
        "--end",
        type=_parse_date,
        default=None,
        help="End filing date (YYYY-MM-DD). Default: today.",
    )
    edgar_p.add_argument(
        "--user-agent",
        default=None,
        help="Contact string sent to SEC (e.g. 'My Org name@org.com').",
    )
    _add_format_arg(edgar_p)

    return parser


def _add_format_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--format",
        choices=("csv", "json", "both"),
        default="csv",
        help="Output format (default: csv).",
    )


def _add_nvd_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--last-days",
        type=int,
        default=None,
        help="Pull CVEs modified in the last N days (incremental).",
    )
    p.add_argument(
        "--start",
        type=_parse_date,
        default=None,
        help="Start of lastModified range (YYYY-MM-DD or ISO-8601).",
    )
    p.add_argument(
        "--end",
        type=_parse_date,
        default=None,
        help="End of lastModified range (YYYY-MM-DD or ISO-8601).",
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = Config.load()
    config.ensure_data_dir()

    if args.command == "kev":
        run_kev(config, args.format)
    elif args.command == "nvd":
        run_nvd(config, args)
    elif args.command == "all":
        run_nvd(config, args)
        run_kev(config, args.format)
    elif args.command == "enrich":
        run_enrich(config, args.format)
    elif args.command == "edgar":
        run_edgar(config, args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
