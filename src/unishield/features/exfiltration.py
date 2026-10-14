"""
UniShield — Exfiltration Feature Extractor

Extracts data exfiltration indicators from flow windows.
Detects unusual outbound data volumes, asymmetric byte ratios,
and long-duration sessions that may indicate data theft.

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication or payload inspection.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.schemas.flow import FlowDirection, NormalisedFlow


class ExfiltrationFeatureExtractor(BaseFeatureExtractor):
    """Extract data exfiltration indicator features."""

    @property
    def name(self) -> str:
        return "exfiltration"

    @property
    def feature_names(self) -> list[str]:
        return [
            "total_outbound_bytes",
            "total_inbound_bytes",
            "outbound_inbound_ratio",
            "max_session_bytes",
            "max_session_duration_sec",
            "long_sessions_count",
            "high_volume_destinations",
            "top_dest_ip",
            "top_dest_bytes",
            "avg_bytes_per_dest",
            "dest_port_rarity",
            "unusual_port_flows",
        ]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        if not flows:
            return {name: 0 for name in self.feature_names}

        # Classify flows by direction
        outbound_bytes = 0
        inbound_bytes = 0
        for f in flows:
            if f.direction == FlowDirection.OUTBOUND:
                outbound_bytes += f.byte_count
            elif f.direction == FlowDirection.INBOUND:
                inbound_bytes += f.byte_count
            else:
                # If direction is unknown, use a heuristic:
                # higher source port → likely outbound
                if f.source_port and f.destination_port:
                    if f.source_port > f.destination_port:
                        outbound_bytes += f.byte_count
                    else:
                        inbound_bytes += f.byte_count

        # Outbound/inbound ratio
        ob_ratio = outbound_bytes / max(inbound_bytes, 1)

        # Per-destination analysis
        dest_bytes: dict[str, int] = defaultdict(int)
        dest_durations: dict[str, float] = defaultdict(float)
        for f in flows:
            dest_bytes[f.destination_ip] += f.byte_count
            if f.duration:
                dest_durations[f.destination_ip] = max(
                    dest_durations[f.destination_ip], f.duration
                )

        # Max session stats
        max_session_bytes = max((f.byte_count for f in flows), default=0)
        max_session_duration = max((f.duration or 0.0 for f in flows), default=0.0)

        # Long sessions (> 1 hour)
        long_sessions = sum(1 for f in flows if f.duration and f.duration > 3600)

        # High-volume destinations (> 10 MB)
        high_vol_dests = [
            ip for ip, b in dest_bytes.items() if b > 10_000_000
        ]

        # Top destination by bytes
        if dest_bytes:
            top_dest = max(dest_bytes.items(), key=lambda x: x[1])
        else:
            top_dest = ("none", 0)

        avg_bytes_per_dest = sum(dest_bytes.values()) / max(len(dest_bytes), 1)

        # Port rarity: fraction of flows using uncommon ports (> 1024)
        port_counter = Counter(
            f.destination_port for f in flows if f.destination_port is not None
        )
        well_known_ports = {80, 443, 53, 22, 25, 110, 143, 993, 995, 587, 8080, 8443}
        unusual_port_flows = sum(
            count for port, count in port_counter.items()
            if port not in well_known_ports and port > 1024
        )
        port_rarity = unusual_port_flows / max(len(flows), 1)

        return {
            "total_outbound_bytes": outbound_bytes,
            "total_inbound_bytes": inbound_bytes,
            "outbound_inbound_ratio": round(ob_ratio, 4),
            "max_session_bytes": max_session_bytes,
            "max_session_duration_sec": round(max_session_duration, 2),
            "long_sessions_count": long_sessions,
            "high_volume_destinations": len(high_vol_dests),
            "top_dest_ip": top_dest[0],
            "top_dest_bytes": top_dest[1],
            "avg_bytes_per_dest": round(avg_bytes_per_dest, 2),
            "dest_port_rarity": round(port_rarity, 4),
            "unusual_port_flows": unusual_port_flows,
        }
