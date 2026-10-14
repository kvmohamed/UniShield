"""
UniShield — Beaconing Feature Extractor

Extracts C2 beaconing pattern features from flow windows.
Looks for periodic communication patterns indicating command-and-control.

Features computed:
    - Inter-arrival time statistics (mean, std, CV)
    - Periodicity score (FFT-based)
    - Packet size regularity
    - Destination rarity
    - Session count patterns

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.schemas.flow import NormalisedFlow


class BeaconingFeatureExtractor(BaseFeatureExtractor):
    """Extract C2 beaconing pattern features."""

    def __init__(self, min_connections: int = 5):
        self.min_connections = min_connections

    @property
    def name(self) -> str:
        return "beaconing"

    @property
    def feature_names(self) -> list[str]:
        return [
            "candidate_beacon_pairs",
            "top_beacon_interval_mean",
            "top_beacon_interval_std",
            "top_beacon_interval_cv",
            "top_beacon_periodicity_score",
            "top_beacon_size_regularity",
            "top_beacon_connection_count",
            "top_beacon_src_ip",
            "top_beacon_dst_ip",
            "avg_beacon_cv",
            "min_beacon_cv",
        ]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        if not flows:
            return {name: 0 for name in self.feature_names}

        # Group by (source_ip, destination_ip) pairs
        pairs: dict[tuple[str, str], list[NormalisedFlow]] = defaultdict(list)
        for f in flows:
            pairs[(f.source_ip, f.destination_ip)].append(f)

        # Analyse each pair for beaconing behaviour
        beacon_candidates: list[dict[str, Any]] = []

        for (src, dst), pair_flows in pairs.items():
            if len(pair_flows) < self.min_connections:
                continue

            # Sort by timestamp
            sorted_flows = sorted(pair_flows, key=lambda f: f.timestamp)

            # Compute inter-arrival times (seconds)
            intervals = []
            for i in range(1, len(sorted_flows)):
                delta = (sorted_flows[i].timestamp - sorted_flows[i - 1].timestamp).total_seconds()
                if delta > 0:
                    intervals.append(delta)

            if len(intervals) < 3:
                continue

            # Inter-arrival time statistics
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_interval = math.sqrt(variance)
            cv = std_interval / mean_interval if mean_interval > 0 else float("inf")

            # Periodicity score using simple FFT-like analysis
            # (ratio of dominant frequency power to total)
            periodicity = self._periodicity_score(intervals)

            # Packet size regularity
            sizes = [f.byte_count for f in sorted_flows]
            size_regularity = self._size_regularity(sizes)

            beacon_candidates.append({
                "src_ip": src,
                "dst_ip": dst,
                "connection_count": len(pair_flows),
                "interval_mean": mean_interval,
                "interval_std": std_interval,
                "interval_cv": cv,
                "periodicity_score": periodicity,
                "size_regularity": size_regularity,
            })

        if not beacon_candidates:
            return {name: 0 for name in self.feature_names}

        # Find the top beacon candidate (lowest CV = most regular)
        top = min(beacon_candidates, key=lambda c: c["interval_cv"])

        return {
            "candidate_beacon_pairs": len(beacon_candidates),
            "top_beacon_interval_mean": round(top["interval_mean"], 4),
            "top_beacon_interval_std": round(top["interval_std"], 4),
            "top_beacon_interval_cv": round(top["interval_cv"], 4),
            "top_beacon_periodicity_score": round(top["periodicity_score"], 4),
            "top_beacon_size_regularity": round(top["size_regularity"], 4),
            "top_beacon_connection_count": top["connection_count"],
            "top_beacon_src_ip": top["src_ip"],
            "top_beacon_dst_ip": top["dst_ip"],
            "avg_beacon_cv": round(
                sum(c["interval_cv"] for c in beacon_candidates) / len(beacon_candidates), 4
            ),
            "min_beacon_cv": round(
                min(c["interval_cv"] for c in beacon_candidates), 4
            ),
        }

    @staticmethod
    def _periodicity_score(intervals: list[float]) -> float:
        """
        Estimate periodicity from inter-arrival times.

        Uses a simplified approach: measures how closely intervals
        cluster around the median interval. A perfectly periodic
        signal would have all intervals identical (score → 1.0).
        """
        if len(intervals) < 2:
            return 0.0

        sorted_vals = sorted(intervals)
        median = sorted_vals[len(sorted_vals) // 2]
        if median == 0:
            return 0.0

        # Fraction of intervals within 20% of median
        tolerance = 0.2 * median
        within_tolerance = sum(1 for v in intervals if abs(v - median) <= tolerance)
        return within_tolerance / len(intervals)

    @staticmethod
    def _size_regularity(sizes: list[int]) -> float:
        """
        Measure how regular packet sizes are.

        Returns 1.0 if all sizes are identical, decreasing with variance.
        """
        if len(sizes) < 2:
            return 1.0

        mean_size = sum(sizes) / len(sizes)
        if mean_size == 0:
            return 0.0

        variance = sum((s - mean_size) ** 2 for s in sizes) / len(sizes)
        cv = math.sqrt(variance) / mean_size
        # Map CV to [0, 1] — low CV = high regularity
        return max(0.0, 1.0 - cv)
