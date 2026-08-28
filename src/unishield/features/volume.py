"""
UniShield — Volume Feature Extractor

Extracts traffic volume and rate features from flow windows.
Used by DDoS/flood detectors.

Features computed:
    - total_packets, total_bytes
    - packets_per_second, bytes_per_second
    - unique_source_ips, unique_dest_ips
    - source_ip_entropy, dest_ip_entropy
    - protocol distribution
    - SYN count, SYN/ACK ratio

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from unishield.features.base import BaseFeatureExtractor
from unishield.schemas.flow import NormalisedFlow, ProtocolType


def _entropy(counter: Counter) -> float:
    """Shannon entropy of a count distribution."""
    total = sum(counter.values())
    if total == 0:
        return 0.0
    probs = [c / total for c in counter.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


class VolumeFeatureExtractor(BaseFeatureExtractor):
    """Extract traffic volume, rate, and distribution features."""

    @property
    def name(self) -> str:
        return "volume"

    @property
    def feature_names(self) -> list[str]:
        return [
            "total_packets",
            "total_bytes",
            "total_flows",
            "window_duration_sec",
            "packets_per_second",
            "bytes_per_second",
            "flows_per_second",
            "unique_source_ips",
            "unique_dest_ips",
            "unique_dest_ports",
            "source_ip_entropy",
            "dest_ip_entropy",
            "dest_port_entropy",
            "tcp_ratio",
            "udp_ratio",
            "icmp_ratio",
            "syn_count",
            "syn_ack_count",
            "syn_ack_ratio",
            "max_packet_count_per_flow",
            "max_byte_count_per_flow",
            "avg_packet_count_per_flow",
            "avg_byte_count_per_flow",
            "dest_concentration",
        ]

    def extract(self, flows: list[NormalisedFlow]) -> dict[str, Any]:
        if not flows:
            return {name: 0.0 for name in self.feature_names}

        total_packets = sum(f.packet_count for f in flows)
        total_bytes = sum(f.byte_count for f in flows)
        total_flows = len(flows)

        # Window duration
        timestamps = [f.timestamp for f in flows]
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        duration = max(duration, 0.001)  # Avoid division by zero

        # Rate metrics
        pps = total_packets / duration
        bps = total_bytes / duration
        fps = total_flows / duration

        # Unique counts
        src_ips = Counter(f.source_ip for f in flows)
        dst_ips = Counter(f.destination_ip for f in flows)
        dst_ports = Counter(f.destination_port for f in flows if f.destination_port is not None)

        # Entropy
        src_entropy = _entropy(src_ips)
        dst_entropy = _entropy(dst_ips)
        port_entropy = _entropy(dst_ports)

        # Protocol distribution
        proto_counter = Counter(f.protocol for f in flows)
        tcp_count = proto_counter.get(ProtocolType.TCP, 0)
        udp_count = proto_counter.get(ProtocolType.UDP, 0)
        icmp_count = proto_counter.get(ProtocolType.ICMP, 0)

        tcp_ratio = tcp_count / total_flows if total_flows > 0 else 0.0
        udp_ratio = udp_count / total_flows if total_flows > 0 else 0.0
        icmp_ratio = icmp_count / total_flows if total_flows > 0 else 0.0

        # TCP flags analysis
        syn_count = sum(
            1 for f in flows
            if f.tcp_flags and "SYN" in f.tcp_flags.upper() and "ACK" not in f.tcp_flags.upper()
        )
        syn_ack_count = sum(
            1 for f in flows
            if f.tcp_flags and "SYN" in f.tcp_flags.upper() and "ACK" in f.tcp_flags.upper()
        )
        syn_ack_ratio = syn_count / max(syn_ack_count, 1)

        # Per-flow stats
        packet_counts = [f.packet_count for f in flows]
        byte_counts = [f.byte_count for f in flows]

        # Destination concentration: max fraction of traffic to a single destination
        if dst_ips:
            max_dst_count = max(dst_ips.values())
            dest_concentration = max_dst_count / total_flows
        else:
            dest_concentration = 0.0

        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_flows": total_flows,
            "window_duration_sec": round(duration, 3),
            "packets_per_second": round(pps, 2),
            "bytes_per_second": round(bps, 2),
            "flows_per_second": round(fps, 2),
            "unique_source_ips": len(src_ips),
            "unique_dest_ips": len(dst_ips),
            "unique_dest_ports": len(dst_ports),
            "source_ip_entropy": round(src_entropy, 4),
            "dest_ip_entropy": round(dst_entropy, 4),
            "dest_port_entropy": round(port_entropy, 4),
            "tcp_ratio": round(tcp_ratio, 4),
            "udp_ratio": round(udp_ratio, 4),
            "icmp_ratio": round(icmp_ratio, 4),
            "syn_count": syn_count,
            "syn_ack_count": syn_ack_count,
            "syn_ack_ratio": round(syn_ack_ratio, 4),
            "max_packet_count_per_flow": max(packet_counts) if packet_counts else 0,
            "max_byte_count_per_flow": max(byte_counts) if byte_counts else 0,
            "avg_packet_count_per_flow": round(sum(packet_counts) / len(packet_counts), 2) if packet_counts else 0.0,
            "avg_byte_count_per_flow": round(sum(byte_counts) / len(byte_counts), 2) if byte_counts else 0.0,
            "dest_concentration": round(dest_concentration, 4),
        }
