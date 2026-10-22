"""
UniShield - Import offline threat-intelligence files

Loads known-bad IPs/CIDRs, domains and JA3 hashes from local files (plain
text, CSV or STIX 2.1 indicators) into the alert database (database.url /
UNISHIELD_DB_URL), where the API and the detection pipeline use them.
Nothing is downloaded: bring the files across to the analyst side yourself.

Usage:
    python scripts/import_intel.py --source abuse-feodo feodo_ipblocklist.csv
    python scripts/import_intel.py --source ja3-list --type ja3 --expires 2026-12-31 ja3.txt
    python scripts/import_intel.py --source partner-stix --append bundle.json
    python scripts/import_intel.py --status
    python scripts/import_intel.py --remove abuse-feodo
    python scripts/import_intel.py --purge-expired
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from unishield.config import get_config
from unishield.intel.indicators import FORMATS, IndicatorError, parse_expiry
from unishield.intel.store import IntelStore, parse_options, read_indicator_file


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("files", nargs="*", type=Path, help="indicator files to import")
    parser.add_argument("--source", help="source name (default: the file name without extension)")
    parser.add_argument("--format", choices=FORMATS, default="auto")
    parser.add_argument("--type", dest="kind", choices=["ip", "cidr", "domain", "ja3"],
                        help="treat every value as this kind (text/CSV files without a type column)")
    parser.add_argument("--expires", help="expiry for indicators without one (YYYY-MM-DD or ISO time)")
    parser.add_argument("--append", action="store_true", help="add to the source instead of replacing it")
    parser.add_argument("--status", action="store_true", help="print the stored indicators per source")
    parser.add_argument("--remove", metavar="SOURCE", help="delete every indicator of a source")
    parser.add_argument("--purge-expired", action="store_true", help="delete expired indicators")
    parser.add_argument("--db", help="database URL (default: database.url)")
    args = parser.parse_args()

    config = get_config()
    store = IntelStore.from_url(args.db or config.database.url)
    if args.remove:
        print(f"Removed {store.remove_source(args.remove)} indicators of {args.remove!r}")
    if args.purge_expired:
        print(f"Purged {store.purge_expired()} expired indicators")

    try:
        expires: datetime | None = parse_expiry(args.expires) if args.expires else None
    except IndicatorError as exc:
        parser.error(str(exc))
    if args.source and len(args.files) > 1 and not args.append:
        parser.error("several files with one --source would replace each other; add --append")

    failed = False
    max_bytes = config.intel.max_file_mb * 1024 * 1024
    for path in args.files:
        source = args.source or path.stem
        try:
            text = read_indicator_file(path, max_bytes)
            summary = store.import_text(text, source, fmt=args.format, filename=path.name,
                                        mode="append" if args.append else "replace",
                                        options=parse_options(config, expires), kind_hint=args.kind)
        except (OSError, IndicatorError) as exc:
            print(f"{path}: not imported — {exc}", file=sys.stderr)
            failed = True
            continue
        kinds = ", ".join(f"{n} {k}" for k, n in summary["by_kind"].items() if n)
        print(f"{path} → {source!r} ({summary['format']}, {summary['mode']}): {summary['accepted']} stored"
              f"{' (' + kinds + ')' if kinds else ''}, {summary['rejected']} rejected, "
              f"{summary['duplicates_in_file']} duplicates")
        for r in summary["rejected_examples"][:10]:
            print(f"    record {r['record']}: {r['value']!r} — {r['reason']}")

    if args.status or not (args.files or args.remove or args.purge_expired):
        print(json.dumps(store.status(), indent=2))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
