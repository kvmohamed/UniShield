"""
UniShield — Scan Feature Extractor

Extracts network scanning pattern features used by port scan
and host scan detectors.

Features computed:
    - Per-source port fan-out, host fan-out
    - Connection rate, failure ratio
    - Vertical vs. horizontal scan indicators
    - Burst detection

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from unishield.features.base import BaseFeatureExtractor
from unishield.schemas.flow import NormalisedFlow


class ScanFeatureExtractor(BaseFeatureExtractor):
    """Extract scanning-pattern features per source IP."""

    @property
    def name(self) -> str:
        return "scan"

    @property
    def feature_names(self) -> list[str]:
        return [
            "unique_dest_ports_per_source",
            "unique_dest_hosts_per_source",
            "connection_rate",
            "failed_connection_ratio",
            "fanout_score",
            "max_vertical_ports",
            "max_horizontal_hosts",
            "burst_connections",
            "scanner_source_ips",
            "top_scanner_ip",
            "top_scanner_port_count",
            "top_scanner_host_count",
        ]

    def extract(self, flows: list[NormalisedFlow]) -> dict[str, Any]:
        if not flows:
            return {name: 0 for name in self.feature_names}

        # Group flows by source IP
        by_source: dict[str, list[NormalisedFlow]] = defaultdict(list)
        for f in flows:
            by_source[f.source_ip].append(f)

        # Compute per-source scan metrics
        source_metrics: list[dict[str, Any]] = []
        for src_ip, src_flows in by_source.items():
            dest_ports = set()
            dest_hosts = set()
            failed = 0
            total = len(src_flows)

            for f in src_flows:
                if f.destination_port is not None:
                    dest_ports.add(f.destination_port)
                dest_hosts.add(f.destination_ip)

                # Heuristic: a "failed" connection has SYN but no
                # SYN-ACK, or very small packet/byte count
                if f.tcp_flags:
                    flags_upper = f.tcp_flags.upper()
                    if "SYN" in flags_upper and "ACK" not in flags_upper:
                        if f.packet_count <= 2:
                            failed += 1
                elif f.packet_count <= 1 and f.byte_count < 100:
                    failed += 1

            failed_ratio = failed / max(total, 1)

            # Fan-out score: normalised measure of how spread connections are
            port_spread = len(dest_ports) / max(total, 1)
            host_spread = len(dest_hosts) / max(total, 1)
            fanout = (port_spread + host_spread) / 2.0

            source_metrics.append({
                "source_ip": src_ip,
                "unique_ports": len(dest_ports),
                "unique_hosts": len(dest_hosts),
                "total_connections": total,
                "failed_ratio": failed_ratio,
                "fanout": fanout,
            })

        # Aggregate across all sources
        if not source_metrics:
            return {name: 0 for name in self.feature_names}

        # Window duration for rate calculation
        timestamps = [f.timestamp for f in flows]
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        duration = max(duration, 0.001)

        # Find top scanner (most unique ports)
        top_scanner = max(source_metrics, key=lambda m: m["unique_ports"])

        # Max vertical scan: most ports on a single host per source
        max_vert = 0
        max_horiz = 0
        for src_ip, src_flows in by_source.items():
            # Vertical: group by dest_host, count unique ports
            host_ports: dict[str, set] = defaultdict(set)
            # Horizontal: group by dest_port, count unique hosts
            port_hosts: dict[int, set] = defaultdict(set)

            for f in src_flows:
                if f.destination_port is not None:
                    host_ports[f.destination_ip].add(f.destination_port)
                    port_hosts[f.destination_port].add(f.destination_ip)

            if host_ports:
                max_vert = max(max_vert, max(len(v) for v in host_ports.values()))
            if port_hosts:
                max_horiz = max(max_horiz, max(len(v) for v in port_hosts.values()))

        # Burst detection: max connections in a 2-second sub-window
        burst = self._detect_burst(flows, burst_window_sec=2)

        # Scanner IPs: sources with above-threshold fan-out
        avg_unique_ports = sum(m["unique_ports"] for m in source_metrics) / len(source_metrics)
        scanner_threshold = max(avg_unique_ports * 2, 10)
        scanner_ips = [m["source_ip"] for m in source_metrics if m["unique_ports"] > scanner_threshold]

        avg_ports = sum(m["unique_ports"] for m in source_metrics) / len(source_metrics)
        avg_hosts = sum(m["unique_hosts"] for m in source_metrics) / len(source_metrics)
        avg_failed = sum(m["failed_ratio"] for m in source_metrics) / len(source_metrics)
        avg_fanout = sum(m["fanout"] for m in source_metrics) / len(source_metrics)

        return {
            "unique_dest_ports_per_source": round(avg_ports, 2),
            "unique_dest_hosts_per_source": round(avg_hosts, 2),
            "connection_rate": round(len(flows) / duration, 2),
            "failed_connection_ratio": round(avg_failed, 4),
            "fanout_score": round(avg_fanout, 4),
            "max_vertical_ports": max_vert,
            "max_horizontal_hosts": max_horiz,
            "burst_connections": burst,
            "scanner_source_ips": len(scanner_ips),
            "top_scanner_ip": top_scanner["source_ip"],
            "top_scanner_port_count": top_scanner["unique_ports"],
            "top_scanner_host_count": top_scanner["unique_hosts"],
        }

    @staticmethod
    def _detect_burst(flows: list[NormalisedFlow], burst_window_sec: int = 2) -> int:
        """Find the maximum number of connections within any burst_window_sec interval."""
        if not flows:
            return 0

        sorted_flows = sorted(flows, key=lambda f: f.timestamp)
        max_burst = 0
        start_idx = 0

        for end_idx in range(len(sorted_flows)):
            # Slide start forward until within burst window
            while start_idx < end_idx:
                delta = (sorted_flows[end_idx].timestamp - sorted_flows[start_idx].timestamp).total_seconds()
                if delta <= burst_window_sec:
                    break
                start_idx += 1
            burst_size = end_idx - start_idx + 1
            max_burst = max(max_burst, burst_size)

        return max_burst
