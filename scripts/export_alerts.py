"""
UniShield - Export stored alerts and incidents to files

Reads alerts from the alert database (database.url / UNISHIELD_DB_URL),
correlates them into incidents and writes JSON lines, CEF and a STIX 2.1
bundle to <export.directory>/on-demand (or --out). Files only: nothing is
sent anywhere.

Usage:
    python scripts/export_alerts.py
    python scripts/export_alerts.py --formats stix --since 2026-10-22T00:00:00Z
    python scripts/export_alerts.py --run-id run-20261022-101500-ab12cd --out exports/case-17
"""

from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path

from unishield.config import get_config
from unishield.export.files import FORMATS, export_stored
from unishield.schemas.timeutil import ensure_utc
from unishield.storage import AlertRepository


def _time(value: str) -> datetime:
    return ensure_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--formats", default=",".join(FORMATS), help="comma-separated: jsonl,cef,stix")
    parser.add_argument("--since", type=_time, help="alerts whose window ends at or after this time")
    parser.add_argument("--until", type=_time, help="alerts whose window ends before this time")
    parser.add_argument("--run-id", help="only alerts of this analysis run")
    parser.add_argument("--no-incidents", action="store_true", help="do not export correlated incidents")
    parser.add_argument("--max-alerts", type=int, default=100_000)
    parser.add_argument("--out", type=Path, help="output directory (default: <export.directory>/on-demand)")
    parser.add_argument("--db", help="database URL (default: database.url)")
    args = parser.parse_args()

    formats = [f.strip() for f in args.formats.split(",") if f.strip()]
    unknown = sorted(set(formats) - set(FORMATS))
    if unknown or not formats:
        parser.error(f"unknown format(s) {unknown}; choose from {', '.join(FORMATS)}")
    config = get_config()
    repository = AlertRepository.from_url(args.db or config.database.url)
    summary = export_stored(repository, config, formats=formats, since=args.since, until=args.until,
                            run_id=args.run_id, include_incidents=False if args.no_incidents else None,
                            max_alerts=args.max_alerts, directory=args.out)
    print(f"Exported {summary['alerts']} alerts and {summary['incidents']} incidents to {summary['directory']}"
          + (f" (first {summary['alerts']} of {summary['alerts_matching']})" if summary["truncated"] else ""))
    for f in summary["files"]:
        print(f"  {f['name']}  {f['bytes']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
