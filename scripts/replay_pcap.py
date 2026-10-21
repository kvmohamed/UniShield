"""
UniShield - Analyse a capture or log file from the command line

Reads a PCAP/PCAPNG, Zeek (JSON/TSV, file or directory) or flow CSV/JSON
file locally, runs the detection pipeline and prints the alerts.
Nothing is sent on any network: the file is only read.

Usage:
    python scripts/replay_pcap.py --input data/samples/attack_portscan.pcap
    python scripts/replay_pcap.py --input data/samples/zeek --mode hybrid --json
"""

from __future__ import annotations

import argparse
from pathlib import Path

from unishield.ingest.detect import open_reader
from unishield.processing.pipeline import Pipeline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--mode", choices=["rules", "hybrid", "ml"], default=None)
    parser.add_argument("--json", action="store_true", help="print alerts as JSON lines")
    args = parser.parse_args()

    reader, fmt = open_reader(args.input)
    result = Pipeline(detection_mode=args.mode).run(reader)
    if args.json:
        for alert in result.alerts:
            print(alert.model_dump_json())
        return
    summary = result.summary()
    print(f"{args.input} ({fmt}): {summary['total_records']} records, {summary['total_windows']} windows, "
          f"{summary['total_alerts']} alerts")
    for a in result.alerts:
        print(f"  {a.window_end:%Y-%m-%d %H:%M:%S}  {a.severity.value:8s} {a.threat_class.value:26s} "
              f"{a.source_ip or '-'} -> {a.destination_ip or '-'}  conf {a.confidence:.2f}  ({a.detector_name})")


if __name__ == "__main__":
    main()
