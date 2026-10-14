"""
UniShield — Volume / DDoS Feature Extractor

Traffic volume and rate features for DDoS and flood detection.

Aggregate features (whole window): totals, average rates over the window's
observed duration, address entropy, protocol mix, SYN counts.

Target features: a flood concentrates on a victim, so three destinations
are profiled separately:
    vol_target_*  — destination receiving the most packets (volumetric)
    syn_target_*  — destination receiving the most half-open attempts (SYN flood)
    udp_target_*  — destination receiving the most UDP packets (UDP flood)
Peak rates are the busiest 1-second interval of the window, with each
flow's packets spread over its duration (see ``peak_per_second``).

A TCP flow is a half-open attempt when its connection state is S0 or REJ,
or — for sources without connection state — when the originator sent SYN
without ACK.

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from unishield.features.base import (
    BaseFeatureExtractor,
    WindowContext,
    entropy,
    peak_per_second,
    resolve_window,
)
from unishield.schemas.flow import NormalisedFlow, ProtocolType

_HALF_OPEN_STATES = {"S0", "REJ"}


def is_half_open(flow: NormalisedFlow) -> bool:
    """TCP connection attempt that was never established."""
    if flow.protocol != ProtocolType.TCP:
        return False
    if flow.conn_state:
        return flow.conn_state in _HALF_OPEN_STATES
    flags = (flow.tcp_flags or "").upper()
    return "SYN" in flags and "ACK" not in flags


def _has_syn_ack(flow: NormalisedFlow) -> bool:
    flags = (flow.tcp_flags or "").upper()
    return "SYN" in flags and "ACK" in flags


class VolumeFeatureExtractor(BaseFeatureExtractor):
    """Extract traffic volume, rate, distribution and per-target flood features."""

    _TARGET_FEATURES = [
        "vol_target_ip", "vol_target_packets", "vol_target_pps_avg", "vol_target_pps_peak",
        "vol_target_bps_peak", "vol_target_unique_sources", "vol_target_source_entropy",
        "syn_target_ip", "syn_target_attempts", "syn_target_rate_peak", "syn_target_syn_only_ratio",
        "syn_target_unique_sources",
        "udp_target_ip", "udp_target_pps_peak", "udp_target_udp_ratio", "udp_target_unique_sources",
        "peak_flows_per_second",
    ]

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
            *self._TARGET_FEATURES,
        ]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        if not flows:
            features: dict[str, Any] = {name: 0.0 for name in self.feature_names}
            features.update(vol_target_ip=None, syn_target_ip=None, udp_target_ip=None)
            return features

        window = resolve_window(flows, window)
        duration = window.observed_seconds
        total_flows = len(flows)
        total_packets = sum(f.packet_count for f in flows)
        total_bytes = sum(f.byte_count for f in flows)

        src_ips = Counter(f.source_ip for f in flows)
        dst_ips = Counter(f.destination_ip for f in flows)
        dst_ports = Counter(f.destination_port for f in flows if f.destination_port is not None)
        protocols = Counter(f.protocol for f in flows)

        syn_count = sum(1 for f in flows if is_half_open(f))
        syn_ack_count = sum(1 for f in flows if _has_syn_ack(f))
        packet_counts = [f.packet_count for f in flows]
        byte_counts = [f.byte_count for f in flows]

        features = {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_flows": total_flows,
            "window_duration_sec": round(duration, 3),
            "packets_per_second": round(total_packets / duration, 2),
            "bytes_per_second": round(total_bytes / duration, 2),
            "flows_per_second": round(total_flows / duration, 2),
            "unique_source_ips": len(src_ips),
            "unique_dest_ips": len(dst_ips),
            "unique_dest_ports": len(dst_ports),
            "source_ip_entropy": round(entropy(src_ips.values()), 4),
            "dest_ip_entropy": round(entropy(dst_ips.values()), 4),
            "dest_port_entropy": round(entropy(dst_ports.values()), 4),
            "tcp_ratio": round(protocols.get(ProtocolType.TCP, 0) / total_flows, 4),
            "udp_ratio": round(protocols.get(ProtocolType.UDP, 0) / total_flows, 4),
            "icmp_ratio": round(protocols.get(ProtocolType.ICMP, 0) / total_flows, 4),
            "syn_count": syn_count,
            "syn_ack_count": syn_ack_count,
            "syn_ack_ratio": round(syn_count / max(syn_ack_count, 1), 4),
            "max_packet_count_per_flow": max(packet_counts),
            "max_byte_count_per_flow": max(byte_counts),
            "avg_packet_count_per_flow": round(total_packets / total_flows, 2),
            "avg_byte_count_per_flow": round(total_bytes / total_flows, 2),
            "dest_concentration": round(max(dst_ips.values()) / total_flows, 4),
            "peak_flows_per_second": round(peak_per_second(flows, window, lambda f: 1), 2),
        }
        features.update(self._target_features(flows, window))
        return features

    @staticmethod
    def _target_features(flows: list[NormalisedFlow], window: WindowContext) -> dict[str, Any]:
        by_dst: dict[str, list[NormalisedFlow]] = defaultdict(list)
        for f in flows:
            by_dst[f.destination_ip].append(f)

        def packets(fs):
            return sum(f.packet_count for f in fs)

        def udp_packets(fs):
            return sum(f.packet_count for f in fs if f.protocol == ProtocolType.UDP)

        def half_open(fs):
            return sum(1 for f in fs if is_half_open(f))

        out: dict[str, Any] = {}

        vol_ip, vol_flows = max(by_dst.items(), key=lambda kv: packets(kv[1]))
        vol_sources = Counter(f.source_ip for f in vol_flows)
        out.update(
            vol_target_ip=vol_ip,
            vol_target_packets=packets(vol_flows),
            vol_target_pps_avg=round(packets(vol_flows) / window.observed_seconds, 2),
            vol_target_pps_peak=round(peak_per_second(vol_flows, window, lambda f: f.packet_count), 2),
            vol_target_bps_peak=round(peak_per_second(vol_flows, window, lambda f: f.byte_count), 2),
            vol_target_unique_sources=len(vol_sources),
            vol_target_source_entropy=round(entropy(vol_sources.values()), 4),
        )

        syn_ip, syn_flows = max(by_dst.items(), key=lambda kv: half_open(kv[1]))
        attempts = half_open(syn_flows)
        tcp_flows = sum(1 for f in syn_flows if f.protocol == ProtocolType.TCP)
        out.update(
            syn_target_ip=syn_ip if attempts else None,
            syn_target_attempts=attempts,
            syn_target_rate_peak=round(peak_per_second(syn_flows, window, lambda f: int(is_half_open(f))), 2),
            syn_target_syn_only_ratio=round(attempts / tcp_flows, 4) if tcp_flows else 0.0,
            syn_target_unique_sources=len({f.source_ip for f in syn_flows if is_half_open(f)}),
        )

        udp_ip, udp_flows = max(by_dst.items(), key=lambda kv: udp_packets(kv[1]))
        udp_total = udp_packets(udp_flows)
        out.update(
            udp_target_ip=udp_ip if udp_total else None,
            udp_target_pps_peak=round(peak_per_second(
                udp_flows, window, lambda f: f.packet_count if f.protocol == ProtocolType.UDP else 0), 2),
            udp_target_udp_ratio=round(udp_total / max(packets(udp_flows), 1), 4),
            udp_target_unique_sources=len({f.source_ip for f in udp_flows if f.protocol == ProtocolType.UDP}),
        )
        return out
