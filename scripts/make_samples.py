"""
UniShield — Write deterministic sample input files to data/samples/

The files are synthetic (private and documentation address ranges) and are
written directly to disk; nothing is sent on any network. Replay them with:

    curl -X POST "http://127.0.0.1:8000/replay/start?file_path=data/samples/sample.pcap"

Usage:
    python scripts/make_samples.py [--out data/samples]
"""

from __future__ import annotations

import argparse
from pathlib import Path

from unishield.data import sample_files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--out", type=Path, default=Path("data/samples"), help="output directory")
    out: Path = parser.parse_args().out

    capture = sample_files.write_sample_pcap(out / "sample.pcap")
    sample_files.write_sample_pcap(out / "sample.pcapng", pcapng=True)
    sample_files.write_sample_zeek_dir(out / "zeek")
    sample_files.write_sample_zeek_tsv(out / "zeek_tsv" / "conn.log")
    sample_files.write_sample_flow_csv(out / "flows.csv")
    sample_files.write_sample_flow_jsonl(out / "flows.jsonl")
    sample_files.write_cicids_style_csv(out / "cicids2017_style.csv")
    sample_files.write_port_scan_pcap(out / "attack_portscan.pcap")
    sample_files.write_syn_flood_pcap(out / "attack_synflood.pcap")

    print(f"Wrote sample inputs to {out.resolve()}:")
    for path in sorted(p for p in out.rglob("*") if p.is_file() and p.name != ".gitkeep"):
        print(f"  {path.relative_to(out)}  ({path.stat().st_size} bytes)")
    print(f"\nsample.pcap: {capture.ip_packets} IP packets, {capture.non_ip_frames} non-IP frame, "
          f"{len(capture.flows)} expected flows")


if __name__ == "__main__":
    main()
