"""Unit tests for the statistical (robust z) and Isolation Forest detectors (audit D5, D6)."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.sample_generator import SimulatedReader, build_scenario
from unishield.detectors.anomaly_detector import ANOMALY_FEATURE_KEYS, AnomalyDetector, anomaly_vector
from unishield.detectors.statistical_detector import StatisticalDetector
from unishield.processing.pipeline import Pipeline
from unishield.schemas.flow import NormalisedFlow

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
FLOWS = [NormalisedFlow(timestamp=T0 + timedelta(seconds=i), source_ip="10.0.0.1", destination_ip="10.0.0.2")
         for i in range(12)]


def window_features(rng, scale=1.0, **overrides):
    f = {
        "packets_per_second": rng.uniform(40, 60) * scale, "bytes_per_second": rng.uniform(4e4, 6e4) * scale,
        "flows_per_second": rng.uniform(0.8, 1.2), "unique_source_ips": rng.randint(8, 12),
        "unique_dest_ips": rng.randint(5, 9), "dns_query_count": rng.randint(2, 5),
        "failed_connection_ratio": rng.uniform(0, 0.05), "total_flows": rng.randint(9, 13),
        "total_packets": rng.randint(400, 600), "total_bytes": rng.randint(400_000, 600_000),
    }
    f.update(overrides)
    return f


class TestStatisticalDetector:
    def _trained(self, windows=40):
        rng, det = random.Random(1), StatisticalDetector()
        for _ in range(windows):
            assert det.detect(FLOWS, window_features(rng), T0, T0) == []
        return rng, det

    def test_simultaneous_spikes_are_reported(self):
        rng, det = self._trained()
        (alert,) = det.detect(FLOWS, window_features(rng, scale=20), T0, T0)
        assert {"packets_per_second", "bytes_per_second"} <= set(alert.evidence["deviating_metrics"])
        assert alert.mitre_techniques == []

    def test_single_metric_spike_is_not_enough(self):
        rng, det = self._trained()
        assert det.detect(FLOWS, window_features(rng, dns_query_count=60), T0, T0) == []

    def test_no_alerts_before_the_baseline_is_ready(self):
        rng, det = self._trained(windows=10)
        assert det.detect(FLOWS, window_features(rng, scale=20), T0, T0) == []

    def test_explained_windows_are_skipped_and_kept_out_of_the_baseline(self):
        rng, det = self._trained()
        size = det.baseline_size
        assert det.detect(FLOWS, window_features(rng, scale=20, rule_alert_classes=["SYN_FLOOD"]), T0, T0) == []
        assert det.baseline_size == size


def tailed_features(rng, shift=0.0):
    """Window features with log-normal (tailed) variation, as real traffic metrics have."""
    def ln(mu, sigma):
        return rng.lognormvariate(mu + shift * sigma, sigma)
    return {
        "total_packets": ln(6.0, 0.3), "total_bytes": ln(13.0, 0.3), "total_flows": ln(2.5, 0.2),
        "packets_per_second": ln(4.0, 0.3), "bytes_per_second": ln(11.0, 0.3), "flows_per_second": ln(0.0, 0.2),
        "unique_source_ips": ln(2.3, 0.2), "unique_dest_ips": ln(1.9, 0.2), "unique_dest_ports": ln(1.5, 0.2),
        "syn_count": ln(0.5, 0.4), "connection_rate": ln(0.0, 0.2), "dns_query_count": ln(1.2, 0.3),
    }


class TestIsolationForest:
    """
    Isolation Forests learn splits only within the training range, so a window
    far outside it scores like the most extreme training windows. Training on
    tailed data (as real traffic is) gives those extremes high scores.
    """

    def _fitted(self, n=300):
        rng, det = random.Random(2), AnomalyDetector()
        det.fit([anomaly_vector(tailed_features(rng)) for _ in range(n)])
        return rng, det

    def test_blatant_window_is_reported_with_percentile_confidence(self):
        rng, det = self._fitted()
        weird = tailed_features(rng, shift=8.0)
        (alert,) = det.detect(FLOWS, weird, T0, T0)
        assert alert.evidence["anomaly_score"] >= 0.6
        assert alert.confidence == alert.evidence["training_percentile"] >= 0.995
        assert len(alert.evidence["most_unusual_features"]) == 3

    def test_typical_window_is_not_reported(self):
        rng, det = self._fitted()
        assert sum(len(det.detect(FLOWS, tailed_features(rng), T0, T0)) for _ in range(100)) <= 1

    def test_explained_and_tiny_windows_are_skipped(self):
        rng, det = self._fitted()
        weird = tailed_features(rng, shift=8.0)
        assert det.detect(FLOWS, dict(weird, rule_alert_classes=["UDP_FLOOD"]), T0, T0) == []
        assert det.detect(FLOWS[:3], weird, T0, T0) == []

    def test_online_warm_up_uses_only_unexplained_windows(self):
        rng, det = random.Random(3), AnomalyDetector(min_training_windows=20)
        for _ in range(30):
            det.detect(FLOWS, window_features(rng, rule_alert_classes=["PORT_SCAN"]), T0, T0)
        assert not det.is_fitted
        for _ in range(20):
            det.detect(FLOWS, window_features(rng), T0, T0)
        assert det.is_fitted

    def test_save_and_load_round_trip(self, tmp_path):
        rng, det = self._fitted()
        path = tmp_path / "iforest.joblib"
        det.save_model(path, extra={"version": "test-1"})
        loaded = AnomalyDetector(model_path=path)
        vec = anomaly_vector(tailed_features(rng, shift=3.0))
        assert loaded.score(vec) == pytest.approx(det.score(vec))
        assert loaded.version == "test-1"

    def test_model_with_other_features_is_rejected(self, tmp_path):
        import joblib
        rng, det = self._fitted()
        path = tmp_path / "bad.joblib"
        det.save_model(path)
        bundle = joblib.load(path)
        bundle["feature_keys"] = ["something_else"]
        joblib.dump(bundle, path)
        with pytest.raises(ValueError):
            AnomalyDetector(model_path=path)

    def test_feature_vector_is_log_scaled_and_tolerant(self):
        vec = anomaly_vector({"total_packets": 1e9, "tcp_ratio": "n/a", "syn_count": -5})
        assert len(vec) == len(ANOMALY_FEATURE_KEYS) and max(vec) < 25 and min(vec) == 0.0


def test_suppressed_repeats_count_as_explained():
    """During an ongoing exfiltration the repeat windows must not become 'unexplained anomalies'."""
    result = Pipeline(enable_correlation=False).run(SimulatedReader(build_scenario("exfil_episodes", 1).flows))
    exfil_times = [f.timestamp for f in build_scenario("exfil_episodes", 1).flows if f.label == "DATA_EXFILTRATION"]
    anomalies = [a for a in result.alerts if a.threat_class.value == "STATISTICAL_ANOMALY"]
    assert all(any(a.window_start <= t < a.window_end for t in exfil_times) for a in anomalies)
