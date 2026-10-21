"""
UniShield — Statistical Anomaly Feature Extractor

Computes statistical features for the Isolation Forest and
Z-score anomaly detectors. Operates on aggregate flow metrics
over a window to detect deviations from learned baselines.

Features produced:
    - Z-scores relative to a rolling baseline
    - Distributional metrics (skewness, kurtosis proxies)
    - Ratio-based anomaly signals

SECURITY CONSTRAINTS:
    - Read-only: no packets sent, no decryption.
    - Baseline is learned from observed data only.
"""

from __future__ import annotations

import math
from collections import deque
from typing import Any

from unishield.features.base import BaseFeatureExtractor, WindowContext, resolve_window
from unishield.schemas.flow import NormalisedFlow


class StatisticalFeatureExtractor(BaseFeatureExtractor):
    """
    Extracts statistical deviation features, maintaining a rolling
    baseline of historical window summaries.
    """

    def __init__(self, baseline_window: int = 50):
        """
        Args:
            baseline_window: Number of past window summaries to keep
                             for computing running mean/std.
        """
        self._baseline_window = baseline_window
        self._history: deque[dict[str, float]] = deque(maxlen=baseline_window)

    @property
    def name(self) -> str:
        return "statistical"

    @property
    def feature_names(self) -> list[str]:
        return [
            "z_packets_per_second",
            "z_bytes_per_second",
            "z_flows_per_second",
            "z_unique_sources",
            "z_unique_dests",
            "z_avg_byte_count",
            "byte_variance",
            "packet_variance",
            "duration_variance",
            "size_skewness_proxy",
            "baseline_samples",
        ]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        if not flows:
            return {name: 0.0 for name in self.feature_names}

        # Compute raw window-level stats
        total_packets = sum(f.packet_count for f in flows)
        total_bytes = sum(f.byte_count for f in flows)
        total_flows = len(flows)

        duration = resolve_window(flows, window).observed_seconds

        pps = total_packets / duration
        bps = total_bytes / duration
        fps = total_flows / duration

        unique_srcs = len(set(f.source_ip for f in flows))
        unique_dsts = len(set(f.destination_ip for f in flows))

        byte_counts = [f.byte_count for f in flows]
        packet_counts = [f.packet_count for f in flows]
        durations = [f.duration for f in flows if f.duration is not None]

        avg_bytes = sum(byte_counts) / len(byte_counts)

        # Variance
        byte_var = self._variance(byte_counts)
        pkt_var = self._variance(packet_counts)
        dur_var = self._variance(durations) if durations else 0.0

        # Skewness proxy (simplified: (mean - median) / std)
        sorted_bytes = sorted(byte_counts)
        median_bytes = sorted_bytes[len(sorted_bytes) // 2]
        byte_std = math.sqrt(byte_var) if byte_var > 0 else 1.0
        skew_proxy = (avg_bytes - median_bytes) / byte_std

        # Current summary for z-score calculation
        current = {
            "pps": pps,
            "bps": bps,
            "fps": fps,
            "unique_srcs": float(unique_srcs),
            "unique_dsts": float(unique_dsts),
            "avg_bytes": avg_bytes,
        }

        # Compute z-scores against baseline
        z_scores = {}
        if len(self._history) >= 3:
            for key in current:
                vals = [h[key] for h in self._history]
                mean = sum(vals) / len(vals)
                std = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals))
                if std > 0:
                    z_scores[key] = (current[key] - mean) / std
                else:
                    z_scores[key] = 0.0
        else:
            z_scores = {k: 0.0 for k in current}

        # Add current to baseline history
        self._history.append(current)

        return {
            "z_packets_per_second": round(z_scores["pps"], 4),
            "z_bytes_per_second": round(z_scores["bps"], 4),
            "z_flows_per_second": round(z_scores["fps"], 4),
            "z_unique_sources": round(z_scores["unique_srcs"], 4),
            "z_unique_dests": round(z_scores["unique_dsts"], 4),
            "z_avg_byte_count": round(z_scores["avg_bytes"], 4),
            "byte_variance": round(byte_var, 2),
            "packet_variance": round(pkt_var, 2),
            "duration_variance": round(dur_var, 4),
            "size_skewness_proxy": round(skew_proxy, 4),
            "baseline_samples": len(self._history),
        }

    @staticmethod
    def _variance(values: list[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return sum((v - mean) ** 2 for v in values) / len(values)

    def reset_baseline(self) -> None:
        """Clear the rolling baseline history."""
        self._history.clear()
