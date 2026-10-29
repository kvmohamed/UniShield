"""
UniShield — Pipeline Orchestrator

Connects ingest → sessionization → normalisation → windowing → feature
extraction → detection → intel enrichment → deduplication into one
streaming pipeline.

DESIGN:
    - Processes records incrementally; a window is analysed as soon as
      traffic time passes its end, and remaining windows are flushed when
      the input ends.
    - Memory is bounded: the window holds at most ``max_records_in_memory``
      records and latency/feature histories keep only recent entries.
    - A pipeline instance runs one input at a time; the API reads its
      counters from another thread (plain integer reads).
    - With a ``PipelineStateStore`` the cross-window state of extractors,
      detectors and the correlator is restored before the first run and
      snapshotted periodically and when a run ends (processing/state_store.py).

SECURITY CONSTRAINTS:
    - Read-only: no packets sent, no endpoints probed.
    - No payload decryption.
    - No blocking or remediation commands.
"""

from __future__ import annotations

import logging
import time
from collections import Counter, deque
from typing import Any, Optional

from unishield.assets import AssetInventory, AssetPolicy
from unishield.config import get_config
from unishield.correlation.correlator import AlertCorrelator
from unishield.detectors.anomaly_detector import AnomalyDetector
from unishield.detectors.base import BaseDetector
from unishield.detectors.beaconing_detector import BeaconingDetector
from unishield.detectors.ddos_detector import DDoSDetector
from unishield.detectors.dns_detector import DNSDetector
from unishield.detectors.encrypted_detector import EncryptedSessionDetector
from unishield.detectors.exfiltration_detector import ExfiltrationDetector
from unishield.detectors.intel_detector import IntelDetector
from unishield.detectors.service_abuse_detector import ServiceAbuseDetector
from unishield.detectors.scan_detector import ScanDetector
from unishield.detectors.statistical_detector import StatisticalDetector
from unishield.features.base import BaseFeatureExtractor, WindowContext
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.features.dns import DNSFeatureExtractor
from unishield.features.encrypted import EncryptedSessionFeatureExtractor
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.features.intel import IntelFeatureExtractor
from unishield.features.service_abuse import ServiceAbuseFeatureExtractor
from unishield.features.scan import ScanFeatureExtractor
from unishield.features.volume import VolumeFeatureExtractor
from unishield.ingest.base import BaseReader
from unishield.intel.enrich import enrich_alerts
from unishield.intel.matcher import IntelMatcher
from unishield.processing.normalization import Normalizer
from unishield.processing.sessionizer import Sessionizer
from unishield.processing.state_store import PipelineStateStore
from unishield.processing.window import SlidingWindow, Window
from unishield.schemas.alert import Alert, SourceType
from unishield.schemas.flow import InputSource, NormalisedFlow
from unishield.schemas.metrics import PipelineMetrics
from unishield.schemas.timeutil import utc_now

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


def _related_flow_id(alert: Alert, records: list[NormalisedFlow]) -> Optional[str]:
    """
    Id of the first flow in the window between the alert's source and
    destination: its flow_id (sessionizer / Zeek uid / CSV) or else its event_id.
    """
    if alert.source_ip is None and alert.destination_ip is None:
        return None
    for f in records:
        if (alert.source_ip is None or f.source_ip == alert.source_ip)                 and (alert.destination_ip is None or f.destination_ip == alert.destination_ip):
            return f.flow_id or f.event_id
    return None


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
    ``alerts`` keeps the most recent ``max_alerts`` alerts (all when None);
    ``total_alerts`` and the per-class counts always cover the whole run.
    """

    def __init__(self, max_alerts: int | None = None):
        self.total_records: int = 0
        self.total_windows: int = 0
        self.total_alerts: int = 0
        self.alerts: list[Alert] = []
        self.max_alerts = max_alerts
        self._class_counts: Counter[str] = Counter()
        self.features_history: deque[dict[str, Any]] = deque(maxlen=_FEATURE_HISTORY)
        # per-window traffic and alert counts of the most recent windows (dashboard analytics)
        self.window_series: deque[dict[str, Any]] = deque(maxlen=_WINDOW_LATENCY_HISTORY)
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.latencies_ms: deque[float] = deque(maxlen=_RECORD_LATENCY_HISTORY)
        self.window_latencies_ms: deque[float] = deque(maxlen=_WINDOW_LATENCY_HISTORY)
        self._latency_sum_ms: float = 0.0
        self.errors: int = 0
        self.ingest: dict[str, Any] = {}
        self.asset_policy: dict[str, Any] = {}
        self.state: Optional[dict[str, Any]] = None

    def add_alert(self, alert: Alert) -> None:
        self.alerts.append(alert)
        if self.max_alerts is not None and len(self.alerts) > self.max_alerts:
            del self.alerts[0]
        self.total_alerts += 1
        self._class_counts[alert.threat_class.value] += 1

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
            "asset_policy": self.asset_policy,
            "state": self.state,
            "ingest": self.ingest,
        }

    def _alerts_by_class(self) -> dict[str, int]:
        return dict(self._class_counts)


DETECTION_MODES = ("rules", "hybrid", "ml")


def default_detectors(mode: str = "rules") -> list[BaseDetector]:
    """
    Default detector set for a detection mode:

        rules  — rule detectors (incl. threat-intel matches) + statistical
                 (robust z) + Isolation Forest
        hybrid — ``rules`` + the supervised window model for windows no rule
                 explained (falls back to ``rules`` when no model is saved)
        ml     — the supervised window model alone (evaluation/ablation)
    """
    if mode not in DETECTION_MODES:
        raise ValueError(f"Unknown detection mode {mode!r}; choose from {DETECTION_MODES}")
    rules: list[BaseDetector] = [
        DDoSDetector(),
        ScanDetector(),
        BeaconingDetector(),
        ExfiltrationDetector(),
        DNSDetector(),
        EncryptedSessionDetector(),
        IntelDetector(),
        ServiceAbuseDetector(),
        StatisticalDetector(),
        AnomalyDetector(),
    ]
    if mode == "rules":
        return rules
    from unishield.detectors.ml_detector import MLDetector

    ml = MLDetector.from_registry(require_unexplained=(mode == "hybrid"))
    if ml is None:
        if mode == "ml":
            raise RuntimeError("Detection mode 'ml' needs a trained model (scripts/train_models.py)")
        logger.warning("No trained window model found; hybrid mode falls back to rules")
        return rules
    return rules + [ml] if mode == "hybrid" else [ml]


class Pipeline:
    """
    Streaming detection pipeline.

    Stages: reader → sessionizer (packet-level readers only) → normaliser
    → event-time sliding window → feature extraction → detectors → intel
    enrichment → deduplication.

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
        window_observer: Any | None = None,
        detection_mode: str | None = None,
        intel: IntelMatcher | None = None,
        assets: AssetInventory | None = None,
        state_store: PipelineStateStore | None = None,
    ):
        """
        Args:
            normalizer: Custom normaliser; default is built from config per run.
            sessionize: Force sessionization on/off; default follows the
                reader's ``packet_level`` attribute (True for PCAP).
            window_observer: Called after each window as
                ``observer(window, features, alerts, rule_classes)`` with the
                alerts before deduplication and the classes the rule stage
                raised or suppressed (dataset building and evaluation).
            detection_mode: ``rules``, ``hybrid`` or ``ml`` for the default
                detector set (see ``default_detectors``); defaults to
                ``models.detection_mode`` in the config.
            intel: Imported threat-intelligence indicators (IntelStore.matcher()).
                Used for INTEL_MATCH alerts, the JA3 blocklist and enriching
                other alerts; ignored when ``intel.enabled`` is false.
            assets: Asset inventory whose role policies are applied to the
                alerts (see ``unishield.assets``); defaults to ``site.assets_file``.
            state_store: Restores cross-window state before the first run and
                snapshots it periodically and at the end of every run.
        """
        config = get_config()
        self._config = config
        self._normalizer_override = normalizer
        self._sessionize = sessionize
        self._reader: BaseReader | None = None

        self.window_size_sec = window_size_sec or config.processing.window_size_sec
        self.slide_interval_sec = slide_interval_sec or config.processing.slide_interval_sec
        self.window = self._new_window()

        # Threat intelligence imported by the operator (empty unless supplied)
        self.intel = intel if intel is not None and config.intel.enabled else IntelMatcher()
        self._intel_escalate = config.intel.escalate_severity
        # Asset roles: applied to alerts after deduplication; the exfiltration
        # extractor also keeps expected uploads (e.g. backups) out of baselines.
        inventory = assets if assets is not None else AssetInventory.from_config()
        self.asset_policy = AssetPolicy(inventory)

        # Feature extractors
        self.extractors = extractors or [
            VolumeFeatureExtractor(),
            ScanFeatureExtractor(),
            BeaconingFeatureExtractor(),
            ExfiltrationFeatureExtractor(assets=inventory),
            DNSFeatureExtractor(),
            EncryptedSessionFeatureExtractor(extra_ja3=self.intel.ja3_labels()),
            IntelFeatureExtractor(self.intel),
            ServiceAbuseFeatureExtractor(),
        ]

        # Detectors: rule detectors first; detectors with runs_after_rules
        # (statistical, anomaly, ML) then see which classes the rules raised.
        self.detection_mode = detection_mode or config.models.detection_mode
        self.detectors = detectors or default_detectors(self.detection_mode)
        self._window_observer = window_observer
        self._last_rule_classes: set[str] = set()
        self.result: PipelineResult | None = None

        # Alert correlation engine
        self._correlator = AlertCorrelator() if enable_correlation else None

        # Optional callback for real-time alert delivery (e.g., to API store)
        self._alert_callback = alert_callback

        # Metrics callback for live metrics delivery to API
        self._metrics_callback: Any | None = None

        self._state_store = state_store
        self._state_restored = False
        self._last_window_end: Any = None

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

    @property
    def state_store(self) -> PipelineStateStore | None:
        return self._state_store

    def _stateful_components(self) -> dict[str, Any]:
        parts: dict[str, Any] = {}
        for kind, items in (("extractor", self.extractors), ("detector", self.detectors)):
            for item in items:
                if hasattr(item, "state_dict") and hasattr(item, "load_state_dict"):
                    parts[f"{kind}:{item.name}"] = item
        if self._correlator is not None:
            parts["correlator"] = self._correlator
        return parts

    def state_dict(self) -> dict[str, Any]:
        """Cross-window state of every stateful extractor, detector and the correlator (JSON-serialisable)."""
        return {name: part.state_dict() for name, part in self._stateful_components().items()}

    def load_state_dict(self, components: dict[str, Any]) -> dict[str, Any]:
        """
        Restore components independently. Returns the names restored and, for
        each one not restored, why (a failing component starts cold).
        """
        restored: list[str] = []
        skipped: dict[str, str] = {}
        parts = self._stateful_components()
        for name, part in parts.items():
            if name not in components:
                skipped[name] = "not in snapshot"
                continue
            try:
                part.load_state_dict(components[name])
                restored.append(name)
            except Exception as e:
                skipped[name] = f"failed: {e}"
                logger.error("Could not restore %s from the state snapshot: %s", name, e)
                fresh_reset = getattr(part, "reset", None)
                if callable(fresh_reset):
                    fresh_reset()
        for name in components:
            if name not in parts:
                skipped[name] = "not in this pipeline"
        return {"restored": sorted(restored), "skipped": skipped}

    def set_metrics_callback(self, callback: Any) -> None:
        """Set a callback for live metrics updates."""
        self._metrics_callback = callback

    def run(self, reader: BaseReader) -> PipelineResult:
        """
        Run the pipeline on a reader (file replay).

        Records flow through windowing incrementally; each window is analysed
        when it closes, and the remaining windows are flushed at end of input.
        """
        result = PipelineResult(self._config.processing.max_alerts_in_memory)
        result.start_time = time.time()
        self.result = result                  # live view for the API while running

        self._is_running = True
        self._should_stop = False
        self._total_records = 0
        self._total_alerts = 0
        self._total_windows = 0
        self._latencies = deque(maxlen=10_000)
        self.window = self._new_window()

        logger.info(
            "Pipeline started: window=%ds, slide=%ds, extractors=%d, detectors=%d, assets=%d",
            self.window_size_sec,
            self.slide_interval_sec,
            len(self.extractors),
            len(self.detectors),
            len(self.asset_policy.inventory),
        )

        if self._state_store is not None and not self._state_restored:
            self._state_store.restore(self)
            self._state_restored = True

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
            result.asset_policy = self.asset_policy.stats()
            if self._state_store is not None:
                self._state_store.save(self, self._last_window_end)
                result.state = self._state_store.stats()
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
        closed_at = utc_now()
        result.total_windows += 1
        self._total_windows += 1

        context = WindowContext(start=window.start, end=window.end,
                                observed_seconds=window.observed_seconds)
        features = self._extract_features(window.records, context)
        result.features_history.append(features)

        alerts = self._run_detectors(window.records, features, window.start, window.end)
        if alerts and not self.intel.empty:
            enrich_alerts(alerts, self.intel, escalate=self._intel_escalate)
        if self._window_observer is not None:
            try:
                self._window_observer(window, features, list(alerts), set(self._last_rule_classes))
            except Exception as e:
                logger.error("Window observer error: %s", e)
        if self._correlator and alerts:
            alerts = self._correlator.deduplicate(alerts)
        alerts = self.asset_policy.apply(alerts)

        source = _ALERT_SOURCE.get(window.records[-1].source_type)
        for alert in alerts:
            if source is not None:
                alert.source_type = source
            if alert.flow_id is None:
                alert.flow_id = _related_flow_id(alert, window.records)
            alert.window_closed_at = closed_at
            alert.emitted_at = utc_now()
            result.add_alert(alert)
            self._total_alerts += 1
            if self._alert_callback:
                try:
                    self._alert_callback(alert)
                except Exception as e:
                    logger.error("Alert callback error: %s", e)

        result.window_latencies_ms.append((time.perf_counter() - started) * 1000.0)
        result.window_series.append({
            "window_start": window.start,
            "window_end": window.end,
            "flows": len(window.records),
            "packets": features.get("total_packets", 0),
            "bytes": features.get("total_bytes", 0),
            "alerts": len(alerts),
            "processing_ms": round(result.window_latencies_ms[-1], 3),
        })
        self._last_window_end = window.end
        if self._state_store is not None:
            self._state_store.maybe_save(self, window.end)

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
        explained |= {a.threat_class.value for a in alerts}
        self._last_rule_classes = explained
        if after:
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
            alerts_suppressed_by_policy=self.asset_policy.suppressed,
            alerts_downgraded_by_policy=self.asset_policy.downgraded,
        )
