"""
UniShield — Pipeline Orchestrator

Connects ingest → windowing → feature extraction → detection into a
single streaming pipeline.

DESIGN:
    - Processes records incrementally as they arrive.
    - Emits alerts without waiting for complete dataset.
    - Measures and reports detection latency.
    - Thread-safe for concurrent access from API endpoints.

SECURITY CONSTRAINTS:
    - Read-only: no packets sent, no endpoints probed.
    - No payload decryption.
    - No blocking or remediation commands.
"""

from __future__ import annotations

import logging
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from unishield.config import get_config, get_thresholds
from unishield.correlation.correlator import AlertCorrelator
from unishield.detectors.base import BaseDetector
from unishield.detectors.ddos_detector import DDoSDetector
from unishield.detectors.scan_detector import ScanDetector
from unishield.detectors.beaconing_detector import BeaconingDetector
from unishield.detectors.exfiltration_detector import ExfiltrationDetector
from unishield.detectors.dns_detector import DNSDetector
from unishield.detectors.anomaly_detector import AnomalyDetector
from unishield.features.base import BaseFeatureExtractor
from unishield.features.volume import VolumeFeatureExtractor
from unishield.features.scan import ScanFeatureExtractor
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.features.dns import DNSFeatureExtractor
from unishield.features.statistical import StatisticalFeatureExtractor
from unishield.ingest.base import BaseReader
from unishield.processing.normalization import Normalizer
from unishield.processing.sessionizer import Sessionizer
from unishield.processing.window import SlidingWindow, WindowManager
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


class PipelineResult:
    """Aggregated result of a full pipeline run."""

    def __init__(self):
        self.total_records: int = 0
        self.total_windows: int = 0
        self.total_alerts: int = 0
        self.alerts: list[Alert] = []
        self.features_history: list[dict[str, Any]] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.latencies_ms: list[float] = []
        self.errors: int = 0
        self.ingest: dict[str, Any] = {}

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
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def latency_p50_ms(self) -> float:
        return self._percentile(50)

    @property
    def latency_p95_ms(self) -> float:
        return self._percentile(95)

    @property
    def latency_p99_ms(self) -> float:
        return self._percentile(99)

    def _percentile(self, p: int) -> float:
        if not self.latencies_ms:
            return 0.0
        sorted_l = sorted(self.latencies_ms)
        idx = int(len(sorted_l) * p / 100)
        idx = min(idx, len(sorted_l) - 1)
        return sorted_l[idx]

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
    → sliding window → feature extraction → detectors → deduplication.

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

        # Windowing
        self.window_manager = WindowManager(
            window_size_sec=self.window_size_sec,
            slide_interval_sec=self.slide_interval_sec,
            max_records=config.processing.max_records_in_memory,
            enable_per_source_windows=True,
        )

        # Feature extractors (default: all built-in including DNS & Statistical)
        self.extractors = extractors or [
            VolumeFeatureExtractor(),
            ScanFeatureExtractor(),
            BeaconingFeatureExtractor(),
            ExfiltrationFeatureExtractor(),
            DNSFeatureExtractor(),
            StatisticalFeatureExtractor(),
        ]

        # Detectors (default: all built-in including DNS & Anomaly)
        self.detectors = detectors or [
            DDoSDetector(),
            ScanDetector(),
            BeaconingDetector(),
            ExfiltrationDetector(),
            DNSDetector(),
            AnomalyDetector(),
        ]

        # Alert correlation engine
        self._correlator = AlertCorrelator() if enable_correlation else None

        # Optional callback for real-time alert delivery (e.g., to API store)
        self._alert_callback = alert_callback

        # Metrics callback for live metrics delivery to API
        self._metrics_callback: Any | None = None

        self._lock = threading.Lock()
        self._is_running = False
        self._should_stop = False

        # Live counters for metrics
        self._total_records: int = 0
        self._total_alerts: int = 0
        self._total_windows: int = 0
        self._latencies: list[float] = []

    @property
    def is_running(self) -> bool:
        return self._is_running

    def set_metrics_callback(self, callback: Any) -> None:
        """Set a callback for live metrics updates."""
        self._metrics_callback = callback

    def run(self, reader: BaseReader) -> PipelineResult:
        """
        Run the pipeline on a reader (file replay).

        Processes records incrementally through windowing, feature
        extraction, and detection.
        """
        result = PipelineResult()
        result.start_time = time.time()

        self._is_running = True
        self._should_stop = False
        self._total_records = 0
        self._total_alerts = 0
        self._total_windows = 0
        self._latencies = []

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

                result.total_records += 1
                self._total_records += 1
                record_start = time.time()

                # Add to window manager
                self.window_manager.add(flow)

                # Check if we should emit a window
                if self.window_manager.global_window.should_emit(flow.timestamp):
                    window_flows = self.window_manager.global_window.emit(flow.timestamp)

                    if window_flows:
                        result.total_windows += 1
                        self._total_windows += 1
                        window_start = self.window_manager.global_window.window_start
                        window_end = self.window_manager.global_window.window_end

                        # Extract features
                        all_features = self._extract_features(window_flows)
                        result.features_history.append(all_features)

                        # Run detectors
                        window_alerts = self._run_detectors(
                            window_flows, all_features, window_start, window_end
                        )

                        # Deduplicate via correlator if enabled
                        if self._correlator and window_alerts:
                            window_alerts = self._correlator.deduplicate(window_alerts)

                        # Collect alerts
                        source = _ALERT_SOURCE.get(window_flows[-1].source_type)
                        for alert in window_alerts:
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

                # Track latency
                latency_ms = (time.time() - record_start) * 1000.0
                result.latencies_ms.append(latency_ms)
                self._latencies.append(latency_ms)

                # Publish live metrics periodically (every 500 records)
                if self._metrics_callback and self._total_records % 500 == 0:
                    try:
                        self._metrics_callback(self.get_metrics())
                    except Exception:
                        pass

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

    def _extract_features(self, flows: list[NormalisedFlow]) -> dict[str, Any]:
        """Run all feature extractors on a window of flows."""
        all_features: dict[str, Any] = {}

        for extractor in self.extractors:
            try:
                features = extractor.extract(flows)
                all_features.update(features)
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
        """Run all detectors on extracted features."""
        alerts: list[Alert] = []

        for detector in self.detectors:
            try:
                detector_alerts = detector.detect(
                    flows, features, window_start, window_end
                )
                alerts.extend(detector_alerts)
            except Exception as e:
                logger.error(
                    "Detector error (%s): %s",
                    detector.name, e, exc_info=True,
                )

        return alerts

    def get_metrics(self) -> PipelineMetrics:
        """Return current pipeline metrics."""
        stats = self.window_manager.stats()

        # Compute live latency percentiles
        latencies = self._latencies[-10000:]  # last 10k for efficiency
        p50 = self._percentile(latencies, 50)
        p95 = self._percentile(latencies, 95)
        p99 = self._percentile(latencies, 99)
        avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

        return PipelineMetrics(
            total_records_ingested=self._total_records,
            total_records_processed=self._total_records,
            total_alerts_generated=self._total_alerts,
            active_windows=self._total_windows,
            window_size_sec=self.window_size_sec,
            slide_interval_sec=self.slide_interval_sec,
            is_processing=self._is_running,
            detectors_loaded=len(self.detectors),
            malformed_records=getattr(self._reader, "errors", 0) or 0,
            latency_p50_ms=round(p50, 3),
            latency_p95_ms=round(p95, 3),
            latency_p99_ms=round(p99, 3),
            latency_avg_ms=round(avg_lat, 3),
        )

    @staticmethod
    def _percentile(values: list[float], p: int) -> float:
        """Compute the p-th percentile of a list of values."""
        if not values:
            return 0.0
        sorted_v = sorted(values)
        idx = min(int(len(sorted_v) * p / 100), len(sorted_v) - 1)
        return sorted_v[idx]
