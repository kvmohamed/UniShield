"""
UniShield — Pipeline Orchestrator

Connects ingest → sessionization → normalisation → windowing → feature
extraction → detection → deduplication into one streaming pipeline.

DESIGN:
    - Processes records incrementally; a window is analysed as soon as
      traffic time passes its end, and remaining windows are flushed when
      the input ends.
    - Memory is bounded: the window holds at most ``max_records_in_memory``
      records and latency/feature histories keep only recent entries.
    - A pipeline instance runs one input at a time; the API reads its
      counters from another thread (plain integer reads).

SECURITY CONSTRAINTS:
    - Read-only: no packets sent, no endpoints probed.
    - No payload decryption.
    - No blocking or remediation commands.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any, Optional

from unishield.config import get_config
from unishield.correlation.correlator import AlertCorrelator
from unishield.detectors.anomaly_detector import AnomalyDetector
from unishield.detectors.base import BaseDetector
from unishield.detectors.beaconing_detector import BeaconingDetector
from unishield.detectors.ddos_detector import DDoSDetector
from unishield.detectors.dns_detector import DNSDetector
from unishield.detectors.exfiltration_detector import ExfiltrationDetector
from unishield.detectors.scan_detector import ScanDetector
from unishield.detectors.statistical_detector import StatisticalDetector
from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.features.dns import DNSFeatureExtractor
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.features.scan import ScanFeatureExtractor
from unishield.features.volume import VolumeFeatureExtractor
from unishield.ingest.base import BaseReader
from unishield.processing.normalization import Normalizer
from unishield.processing.sessionizer import Sessionizer
from unishield.processing.window import SlidingWindow, Window
from unishield.schemas.alert import Alert, SourceType
from unishield.schemas.flow import InputSource, NormalisedFlow
from unishield.schemas.metrics import PipelineMetrics

logger = logging.getLogger("unishield.processing.pipeline")

# Provenance of flows → provenance reported on alerts
_ALERT_SOURCE = {
    InputSource.PCAP: SourceType.PCAP_FILE,
    InputSource.PCAP_REPLAY: SourceType.PCAP_REPLAY,
    InputSource.ZEEK_JSON: SourceType.ZEEK_LOG,
    InputSource.ZEEK_TSV: SourceType.ZEEK_LOG,
    InputSource.FLOW_CSV: SourceType.FLOW_CSV,
    InputSource.FLOW_JSON: SourceType.FLOW_JSON,
    InputSource.SIMULATED: SourceType.SIMULATED,
}

_RECORD_LATENCY_HISTORY = 100_000
_WINDOW_LATENCY_HISTORY = 10_000
_FEATURE_HISTORY = 1_000


def _percentile(values, p: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * p / 100), len(ordered) - 1)]


class PipelineResult:
    """
    Aggregated result of a pipeline run.

    Latency percentiles cover the most recent 100k records / 10k windows;
    ``features_history`` keeps the features of the most recent 1,000 windows.
    """

    def __init__(self):
        self.total_records: int = 0
        self.total_windows: int = 0
        self.total_alerts: int = 0
        self.alerts: list[Alert] = []
        self.features_history: deque[dict[str, Any]] = deque(maxlen=_FEATURE_HISTORY)
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.latencies_ms: deque[float] = deque(maxlen=_RECORD_LATENCY_HISTORY)
        self.window_latencies_ms: deque[float] = deque(maxlen=_WINDOW_LATENCY_HISTORY)
        self._latency_sum_ms: float = 0.0
        self.errors: int = 0
        self.ingest: dict[str, Any] = {}

    def record_latency(self, latency_ms: float) -> None:
        self.latencies_ms.append(latency_ms)
        self._latency_sum_ms += latency_ms

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def records_per_second(self) -> float:
        d = self.duration_seconds
        return self.total_records / d if d > 0 else 0.0

    @property
    def latency_avg_ms(self) -> float:
        return self._latency_sum_ms / self.total_records if self.total_records else 0.0

    @property
    def latency_p50_ms(self) -> float:
        return _percentile(self.latencies_ms, 50)

    @property
    def latency_p95_ms(self) -> float:
        return _percentile(self.latencies_ms, 95)

    @property
    def latency_p99_ms(self) -> float:
        return _percentile(self.latencies_ms, 99)

    def summary(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "total_windows": self.total_windows,
            "total_alerts": self.total_alerts,
            "duration_seconds": round(self.duration_seconds, 3),
            "records_per_second": round(self.records_per_second, 2),
            "latency_avg_ms": round(self.latency_avg_ms, 2),
            "latency_p50_ms": round(self.latency_p50_ms, 2),
            "latency_p95_ms": round(self.latency_p95_ms, 2),
            "latency_p99_ms": round(self.latency_p99_ms, 2),
            "window_processing_p50_ms": round(_percentile(self.window_latencies_ms, 50), 2),
            "window_processing_p95_ms": round(_percentile(self.window_latencies_ms, 95), 2),
            "errors": self.errors,
            "alerts_by_class": self._alerts_by_class(),
            "ingest": self.ingest,
        }

    def _alerts_by_class(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for a in self.alerts:
            key = a.threat_class.value
            counts[key] = counts.get(key, 0) + 1
        return counts


class Pipeline:
    """
    Streaming detection pipeline.

    Stages: reader → sessionizer (packet-level readers only) → normaliser
    → event-time sliding window → feature extraction → detectors → deduplication.

    Usage:
        pipeline = Pipeline()
        result = pipeline.run(reader)
    """

    def __init__(
        self,
        window_size_sec: int | None = None,
        slide_interval_sec: int | None = None,
        extractors: list[BaseFeatureExtractor] | None = None,
        detectors: list[BaseDetector] | None = None,
        alert_callback: Any | None = None,
        enable_correlation: bool = True,
        normalizer: Normalizer | None = None,
        sessionize: bool | None = None,
    ):
        """
        Args:
            normalizer: Custom normaliser; default is built from config per run.
            sessionize: Force sessionization on/off; default follows the
                reader's ``packet_level`` attribute (True for PCAP).
        """
        config = get_config()
        self._config = config
        self._normalizer_override = normalizer
        self._sessionize = sessionize
        self._reader: BaseReader | None = None

        self.window_size_sec = window_size_sec or config.processing.window_size_sec
        self.slide_interval_sec = slide_interval_sec or config.processing.slide_interval_sec
        self.window = self._new_window()

        # Feature extractors
        self.extractors = extractors or [
            VolumeFeatureExtractor(),
            ScanFeatureExtractor(),
            BeaconingFeatureExtractor(),
            ExfiltrationFeatureExtractor(),
            DNSFeatureExtractor(),
        ]

        # Detectors: rule detectors first; detectors with runs_after_rules
        # (statistical, anomaly) then see which classes the rules raised.
        self.detectors = detectors or [
            DDoSDetector(),
            ScanDetector(),
            BeaconingDetector(),
            ExfiltrationDetector(),
            DNSDetector(),
            StatisticalDetector(),
            AnomalyDetector(),
        ]

        # Alert correlation engine
        self._correlator = AlertCorrelator() if enable_correlation else None

        # Optional callback for real-time alert delivery (e.g., to API store)
        self._alert_callback = alert_callback

        # Metrics callback for live metrics delivery to API
        self._metrics_callback: Any | None = None

        self._is_running = False
        self._should_stop = False

        # Live counters for metrics
        self._total_records: int = 0
        self._total_alerts: int = 0
        self._total_windows: int = 0
        self._latencies: deque[float] = deque(maxlen=10_000)

    def _new_window(self) -> SlidingWindow:
        p = self._config.processing
        return SlidingWindow(
            window_size_sec=self.window_size_sec,
            slide_interval_sec=self.slide_interval_sec,
            max_records=p.max_records_in_memory,
            allowed_lateness_sec=p.allowed_lateness_sec,
        )

    @property
    def is_running(self) -> bool:
        return self._is_running

    def set_metrics_callback(self, callback: Any) -> None:
        """Set a callback for live metrics updates."""
        self._metrics_callback = callback

    def run(self, reader: BaseReader) -> PipelineResult:
        """
        Run the pipeline on a reader (file replay).

        Records flow through windowing incrementally; each window is analysed
        when it closes, and the remaining windows are flushed at end of input.
        """
        result = PipelineResult()
        result.start_time = time.time()

        self._is_running = True
        self._should_stop = False
        self._total_records = 0
        self._total_alerts = 0
        self._total_windows = 0
        self._latencies = deque(maxlen=10_000)
        self.window = self._new_window()

        logger.info(
            "Pipeline started: window=%ds, slide=%ds, extractors=%d, detectors=%d",
            self.window_size_sec,
            self.slide_interval_sec,
            len(self.extractors),
            len(self.detectors),
        )

        self._reader = reader
        normalizer = self._normalizer_override or Normalizer.from_config(self._config)
        packet_level = getattr(reader, "packet_level", False) if self._sessionize is None \
            else self._sessionize
        sessionizer = Sessionizer.from_config(self._config) if packet_level else None

        records = reader.read()
        if sessionizer is not None:
            records = sessionizer.process(records)
        records = normalizer.normalize_stream(records)

        try:
            for flow in records:
                if self._should_stop:
                    logger.info("Pipeline stopped by request")
                    break

                record_start = time.perf_counter()
                result.total_records += 1
                self._total_records += 1

                for window in self.window.add(flow):
                    self._process_window(window, result)

                latency_ms = (time.perf_counter() - record_start) * 1000.0
                result.record_latency(latency_ms)
                self._latencies.append(latency_ms)

                # Publish live metrics periodically (every 500 records)
                if self._metrics_callback and self._total_records % 500 == 0:
                    try:
                        self._metrics_callback(self.get_metrics())
                    except Exception:
                        pass

            if not self._should_stop:
                for window in self.window.flush():
                    self._process_window(window, result)

        except Exception as e:
            logger.error("Pipeline error: %s", e, exc_info=True)
            result.errors += 1
        finally:
            self._is_running = False
            result.end_time = time.time()
            result.ingest = {
                "reader": type(reader).__name__,
                "records_read": getattr(reader, "records_read", None),
                "reader_errors": getattr(reader, "errors", None),
                "sessionizer": sessionizer.stats() if sessionizer is not None else None,
                "normalizer": normalizer.stats(),
                "windowing": self.window.stats(),
            }
            # Push final metrics
            if self._metrics_callback:
                try:
                    self._metrics_callback(self.get_metrics())
                except Exception:
                    pass

        logger.info(
            "Pipeline complete: %d records, %d windows, %d alerts in %.2fs",
            result.total_records,
            result.total_windows,
            result.total_alerts,
            result.duration_seconds,
        )

        return result

    def stop(self) -> None:
        """Signal the pipeline to stop processing."""
        self._should_stop = True

    def _process_window(self, window: Window, result: PipelineResult) -> None:
        """Extract features, run detectors and deliver alerts for one closed window."""
        started = time.perf_counter()
        result.total_windows += 1
        self._total_windows += 1

        context = WindowContext(start=window.start, end=window.end,
                                observed_seconds=window.observed_seconds)
        features = self._extract_features(window.records, context)
        result.features_history.append(features)

        alerts = self._run_detectors(window.records, features, window.start, window.end)
        if self._correlator and alerts:
            alerts = self._correlator.deduplicate(alerts)

        source = _ALERT_SOURCE.get(window.records[-1].source_type)
        for alert in alerts:
            if source is not None:
                alert.source_type = source
            result.alerts.append(alert)
            result.total_alerts += 1
            self._total_alerts += 1
            if self._alert_callback:
                try:
                    self._alert_callback(alert)
                except Exception as e:
                    logger.error("Alert callback error: %s", e)

        result.window_latencies_ms.append((time.perf_counter() - started) * 1000.0)

    def _extract_features(
        self, flows: list[NormalisedFlow], window: WindowContext | None = None
    ) -> dict[str, Any]:
        """Run all feature extractors on a window of flows."""
        all_features: dict[str, Any] = {}

        for extractor in self.extractors:
            try:
                all_features.update(extractor.extract(flows, window))
            except Exception as e:
                logger.error(
                    "Feature extraction error (%s): %s",
                    extractor.name, e, exc_info=True,
                )

        return all_features

    def _run_detectors(
        self,
        flows: list[NormalisedFlow],
        features: dict[str, Any],
        window_start: Any,
        window_end: Any,
    ) -> list[Alert]:
        """
        Run rule detectors, then detectors marked ``runs_after_rules`` with
        ``features["rule_alert_classes"]`` set to the classes the rules raised.
        """
        alerts: list[Alert] = []
        first = [d for d in self.detectors if not getattr(d, "runs_after_rules", False)]
        after = [d for d in self.detectors if getattr(d, "runs_after_rules", False)]

        explained: set[str] = set()
        for detector in first:
            alerts.extend(self._safe_detect(detector, flows, features, window_start, window_end))
            explained |= {c.value for c in getattr(detector, "suppressed_classes", ())}
        if after:
            explained |= {a.threat_class.value for a in alerts}
            staged = dict(features, rule_alert_classes=sorted(explained))
            for detector in after:
                alerts.extend(self._safe_detect(detector, flows, staged, window_start, window_end))
        return alerts

    @staticmethod
    def _safe_detect(detector, flows, features, window_start, window_end) -> list[Alert]:
        try:
            return detector.detect(flows, features, window_start, window_end)
        except Exception as e:
            logger.error("Detector error (%s): %s", detector.name, e, exc_info=True)
            return []

    def get_metrics(self) -> PipelineMetrics:
        """Return current pipeline metrics."""
        latencies = list(self._latencies)
        window = self.window
        return PipelineMetrics(
            total_records_ingested=self._total_records,
            total_records_processed=self._total_records - window.late_dropped,
            total_alerts_generated=self._total_alerts,
            active_windows=self._total_windows,
            window_size_sec=self.window_size_sec,
            slide_interval_sec=self.slide_interval_sec,
            is_processing=self._is_running,
            detectors_loaded=len(self.detectors),
            queue_size=window.size,
            queue_capacity=window.max_records,
            dropped_records=window.late_dropped + window.overflow_evicted,
            malformed_records=getattr(self._reader, "errors", 0) or 0,
            latency_p50_ms=round(_percentile(latencies, 50), 3),
            latency_p95_ms=round(_percentile(latencies, 95), 3),
            latency_p99_ms=round(_percentile(latencies, 99), 3),
            latency_avg_ms=round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        )
