"""
UniShield — Statistical (robust z-score) Detector

Compares each window's traffic metrics with a rolling baseline of recent
windows using the median and median absolute deviation (MAD), which are not
dragged around by the outliers they are meant to find.

DESIGN:
    - Runs after the rule detectors. Windows a rule already explained are
      neither reported nor added to the baseline (vetted baseline).
    - Metrics: packets/s, bytes/s, flows/s, unique sources, unique
      destinations, DNS queries, failed-connection ratio.
    - Robust z = (value - median) / (1.4826 * MAD), with a floor on the scale
      (10% of the median, and a small absolute minimum) so a perfectly flat
      baseline does not turn tiny changes into huge scores.
    - STATISTICAL_ANOMALY when at least ``min_deviating_metrics`` metrics are
      at least ``mad_threshold`` above the baseline, after
      ``min_samples_for_baseline`` baseline windows. Only increases are
      reported (a drop in traffic is not treated as a threat here).

Confidence is a rule score (max z / twice the threshold), not a probability.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any

from unishield.config import get_thresholds
from unishield.correlation.mitre_mapping import techniques_for
from unishield.detectors.base import BaseDetector
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import NormalisedFlow

# metric → absolute minimum scale (so a constant baseline still needs a real change)
METRICS: dict[str, float] = {
    "packets_per_second": 5.0,
    "bytes_per_second": 5_000.0,
    "flows_per_second": 0.5,
    "unique_source_ips": 2.0,
    "unique_dest_ips": 2.0,
    "dns_query_count": 3.0,
    "failed_connection_ratio": 0.05,
}


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


class StatisticalDetector(BaseDetector):
    """Robust z-score detector over a vetted rolling baseline."""

    runs_after_rules = True

    def __init__(self, thresholds: dict[str, Any] | None = None):
        if thresholds is None:
            thresholds = get_thresholds().get("statistical", {})
        super().__init__(thresholds)
        self._history: deque[dict[str, float]] = deque(maxlen=thresholds.get("baseline_windows", 120))

    @property
    def name(self) -> str:
        return "statistical_detector"

    @property
    def threat_classes(self) -> list[ThreatClass]:
        return [ThreatClass.STATISTICAL_ANOMALY]

    @property
    def mitre_techniques(self) -> list[str]:
        return techniques_for(ThreatClass.STATISTICAL_ANOMALY)

    @property
    def baseline_size(self) -> int:
        return len(self._history)

    def detect(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        start_time = time.time()
        self._windows_analysed += 1
        if not flows or not features or features.get("rule_alert_classes"):
            return []

        t = self._thresholds
        threshold = t.get("mad_threshold", 3.5)
        min_samples = t.get("min_samples_for_baseline", 30)
        min_metrics = t.get("min_deviating_metrics", 2)
        current = {m: float(features.get(m) or 0.0) for m in METRICS}
        alerts: list[Alert] = []

        if len(self._history) >= min_samples:
            deviations = {}
            for metric, floor in METRICS.items():
                values = [h[metric] for h in self._history]
                median = _median(values)
                mad = _median([abs(v - median) for v in values])
                scale = max(1.4826 * mad, 0.1 * abs(median), floor)
                z = (current[metric] - median) / scale
                if z >= threshold:
                    deviations[metric] = {"value": round(current[metric], 3), "baseline_median": round(median, 3),
                                          "robust_z": round(z, 2)}
            if len(deviations) >= min_metrics:
                max_z = max(d["robust_z"] for d in deviations.values())
                alerts.append(Alert(
                    window_start=window_start,
                    window_end=window_end,
                    threat_class=ThreatClass.STATISTICAL_ANOMALY,
                    severity=Severity.MEDIUM if max_z >= 2 * threshold else Severity.LOW,
                    confidence=round(min(1.0, max_z / (2 * threshold)), 4),
                    detector_name=self.name,
                    model_version=self.version,
                    evidence={
                        "deviating_metrics": deviations,
                        "mad_threshold": threshold,
                        "baseline_windows": len(self._history),
                    },
                    mitre_techniques=techniques_for(ThreatClass.STATISTICAL_ANOMALY),
                    detection_latency_ms=self._measure_latency(start_time),
                ))
                self._alerts_generated += 1

        if not alerts:
            self._history.append(current)
        return alerts
