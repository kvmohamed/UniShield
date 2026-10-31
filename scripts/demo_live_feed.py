"""
UniShield - Live-input demo feed (loopback NetFlow/IPFIX exporter, Zeek log writer)

Plays a synthetic scenario in real time, shifted to the current time, so the
live inputs can be tried without a router or a Zeek sensor:

    netflow  sends NetFlow v5 or IPFIX datagrams to the collector started by
             POST /live/netflow/start. Destinations must be loopback IP
             literals: this script stands in for an exporter on the same
             machine and refuses to send anywhere else.
    zeek     appends conn.log (and dns.log) JSON lines to a directory followed
             by POST /live/zeek/start.

Synthetic data only. UniShield itself never sends; this demo is the sender.

Usage:
    python scripts/demo_live_feed.py netflow --scenario port_scan --speed 5
    python scripts/demo_live_feed.py netflow --format ipfix --port 2055
    python scripts/demo_live_feed.py zeek data/live_zeek --scenario dns_tunnel
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from unishield.data.flow_export_samples import encode_ipfix, encode_v5
from unishield.data.sample_generator import SCENARIO_NAMES, build_scenario
from unishield.schemas.flow import NormalisedFlow, ProtocolType

_HISTORY = {"SYN": "S", "ACK": "A", "PSH": "D", "FIN": "F", "RST": "R"}


def loopback_destination(host: str) -> str:
    """The destination if it is a loopback IP literal; anything else is refused (no name lookup)."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise SystemExit(f"Refusing {host!r}: give a loopback IP literal such as 127.0.0.1 or ::1")
    if not address.is_loopback:
        raise SystemExit(f"Refusing {host}: the demo exporter only sends to the loopback interface")
    return host


def _paced(flows: list[NormalisedFlow], speed: float, batch_sec: float):
    """Yield batches of flows re-timed to start now, sleeping so they arrive at ``speed`` x their pace."""
    flows = sorted(flows, key=lambda f: f.timestamp)
    t0, wall0 = flows[0].timestamp, time.monotonic()
    shift = datetime.now(timezone.utc) - t0
    batch: list[NormalisedFlow] = []
    batch_start = 0.0
    for flow in flows:
        offset = (flow.timestamp - t0).total_seconds()
        if batch and offset - batch_start >= batch_sec:
            yield batch
            batch = []
        if not batch:                                        # wait until this batch's traffic time is due
            batch_start = offset
            delay = offset / speed - (time.monotonic() - wall0)
            if delay > 0:
                time.sleep(delay)
        batch.append(flow.model_copy(update={"timestamp": flow.timestamp + shift}))
    if batch:
        yield batch


def run_netflow(args: argparse.Namespace, flows: list[NormalisedFlow]) -> None:
    host = loopback_destination(args.host)
    ipv4 = [f for f in flows if ":" not in f.source_ip and ":" not in f.destination_ip]
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sent = datagrams = 0
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        for batch in _paced(ipv4, args.speed, args.batch):
            for i in range(0, len(batch), 30):
                chunk = batch[i:i + 30]
                now = datetime.now(timezone.utc)
                if args.format == "v5":
                    data = encode_v5(chunk, now, sequence=sent)
                else:
                    data = encode_ipfix(chunk, now, biflow=True, sequence=sent)
                sock.sendto(data, (host, args.port))
                sent += len(chunk)
                datagrams += 1
            print(f"\r{sent}/{len(ipv4)} flows in {datagrams} datagrams", end="", flush=True)
    print(f"\nSent {sent} flows to {host}:{args.port} ({args.format})")


def _zeek_records(flow: NormalisedFlow) -> tuple[dict, dict | None]:
    uid = "C" + uuid.uuid4().hex[:17]
    flags = {f.strip() for f in (flow.tcp_flags or "").split(",") if f.strip()}
    history = "".join(_HISTORY[f] for f in ("SYN", "ACK", "PSH", "FIN", "RST") if f in flags)
    state = "S0" if flags == {"SYN"} else ("REJ" if "RST" in flags else "SF")
    conn = {"ts": flow.timestamp.timestamp(), "uid": uid, "id.orig_h": flow.source_ip,
            "id.orig_p": flow.source_port, "id.resp_h": flow.destination_ip, "id.resp_p": flow.destination_port,
            "proto": flow.protocol.value.lower() if flow.protocol != ProtocolType.OTHER else "unknown_transport",
            "duration": flow.duration, "orig_bytes": flow.orig_bytes if flow.orig_bytes is not None else
            flow.byte_count, "resp_bytes": flow.resp_bytes or 0,
            "orig_pkts": flow.orig_packets if flow.orig_packets is not None else flow.packet_count,
            "resp_pkts": flow.resp_packets or 0, "conn_state": state}
    if flow.protocol == ProtocolType.TCP and history:
        conn["history"] = history
    dns = None
    if flow.dns_query:
        dns = {"ts": conn["ts"], "uid": uid, "id.orig_h": flow.source_ip, "id.orig_p": flow.source_port,
               "id.resp_h": flow.destination_ip, "id.resp_p": flow.destination_port, "proto": conn["proto"],
               "query": flow.dns_query, "qtype_name": flow.dns_record_type or "A",
               "rcode_name": flow.dns_rcode or "NOERROR"}
    return conn, dns


def run_zeek(args: argparse.Namespace, flows: list[NormalisedFlow]) -> None:
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = 0
    for batch in _paced(flows, args.speed, args.batch):
        conn_lines, dns_lines = [], []
        for flow in batch:
            conn, dns = _zeek_records(flow)
            conn_lines.append(json.dumps(conn))
            if dns is not None:
                dns_lines.append(json.dumps(dns))
        if dns_lines:                                        # Zeek writes dns.log before the connection closes
            with open(directory / "dns.log", "a", encoding="utf-8") as f:
                f.write("\n".join(dns_lines) + "\n")
        with open(directory / "conn.log", "a", encoding="utf-8") as f:
            f.write("\n".join(conn_lines) + "\n")
        written += len(batch)
        print(f"\r{written}/{len(flows)} connections written", end="", flush=True)
    print(f"\nWrote {written} connections to {directory / 'conn.log'}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = parser.add_subparsers(dest="mode", required=True)
    for name in ("netflow", "zeek"):
        p = sub.add_parser(name)
        p.add_argument("--scenario", choices=SCENARIO_NAMES, default="port_scan")
        p.add_argument("--seed", type=int, default=1)
        p.add_argument("--speed", type=float, default=1.0, help="x real time")
        p.add_argument("--batch", type=float, default=1.0, help="seconds of traffic per datagram/write batch")
        if name == "netflow":
            p.add_argument("--host", default="127.0.0.1", help="loopback IP literal of the collector")
            p.add_argument("--port", type=int, default=2055)
            p.add_argument("--format", choices=("v5", "ipfix"), default="ipfix")
        else:
            p.add_argument("directory", help="Zeek log directory the API follows")
    args = parser.parse_args()
    if args.speed <= 0:
        sys.exit("--speed must be positive")
    flows = build_scenario(args.scenario, args.seed).flows
    try:
        (run_netflow if args.mode == "netflow" else run_zeek)(args, flows)
    except KeyboardInterrupt:
        print("\nStopped")


if __name__ == "__main__":
    main()
