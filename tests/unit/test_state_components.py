"""State of each restart-safe component survives a JSON round trip unchanged."""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone

import pytest

from unishield.correlation.correlator import AlertCorrelator
from unishield.data.sample_generator import SimulatedReader, build_scenario, save_sample_flows
from unishield.detectors.anomaly_detector import ANOMALY_FEATURE_KEYS, AnomalyDetector
from unishield.detectors.base import ReportMemory
from unishield.detectors.statistical_detector import METRICS, StatisticalDetector
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Severity
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType
from unishield.schemas.timeutil import from_epoch_us, to_epoch_us

T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)


def roundtrip(state):
    return json.loads(json.dumps(state, allow_nan=False))


def flow(t, src="10.0.1.5", dst="203.0.113.7", up=200_000):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=50000, destination_port=443, protocol=ProtocolType.TCP, packet_count=10,
                          byte_count=up + 500, orig_bytes=up, resp_bytes=500, duration=0.5, conn_state="SF",
                          direction=FlowDirection.OUTBOUND)


def test_epoch_microseconds_are_exact():
    t = datetime(2026, 3, 1, 12, 30, 15, 123457, tzinfo=timezone.utc)
    assert to_epoch_us(t) == 1772368215123457 and from_epoch_us(to_epoch_us(t)) == t


def test_beaconing_extractor_roundtrip():
    ext = BeaconingFeatureExtractor()
    ext.extract([flow(30 * i, dst=f"203.0.113.{i % 3}") for i in range(20)])
    copy = BeaconingFeatureExtractor()
    copy.load_state_dict(roundtrip(ext.state_dict()))
    assert copy._pairs == ext._pairs and copy._dst_sources == ext._dst_sources
    assert list(copy._pairs) == list(ext._pairs)                          # LRU order kept
    nxt = [flow(600 + 30 * i, dst="203.0.113.0") for i in range(2)]
    assert copy.extract(nxt) == ext.extract(nxt)


def test_beaconing_restore_respects_this_instances_limits():
    ext = BeaconingFeatureExtractor()
    ext.extract([flow(i, dst=f"203.0.113.{i}") for i in range(30)])
    small = BeaconingFeatureExtractor(max_pairs=5, max_per_pair=2)
    small.load_state_dict(ext.state_dict())
    assert list(small._pairs) == list(ext._pairs)[-5:]


def test_exfiltration_extractor_roundtrip():
    ext = ExfiltrationFeatureExtractor()
    for w in range(12):
        ext.extract([flow(5 * w, up=150_000 + 1000 * w)])
    copy = ExfiltrationFeatureExtractor()
    copy.load_state_dict(roundtrip(ext.state_dict()))
    assert copy._baselines == ext._baselines and copy._uploaders == ext._uploaders
    nxt = [flow(100, up=3_000_000)]
    assert copy.extract(nxt) == ext.extract(nxt)


def window_features(rng, scale=1.0):
    return {m: rng.uniform(90, 110) * scale for m in METRICS}


def test_statistical_baseline_roundtrip_alerts_without_new_warm_up():
    rng = random.Random(1)
    flows = [flow(0)] * 10
    det = StatisticalDetector()
    for _ in range(40):
        det.detect(flows, window_features(rng), T0, T0)
    restored, cold = StatisticalDetector(), StatisticalDetector()
    restored.load_state_dict(roundtrip(det.state_dict()))
    assert restored.baseline_size == det.baseline_size == 40
    spike = window_features(rng, scale=10.0)
    assert len(restored.detect(flows, spike, T0, T0)) == 1
    assert cold.detect(flows, spike, T0, T0) == []                       # no baseline yet


class TestIsolationForest:
    def windows(self, n, seed=2):
        rng = random.Random(seed)
        return [{k: rng.uniform(1, 100) for k in ANOMALY_FEATURE_KEYS} for _ in range(n)]

    def test_fitted_online_model_is_rebuilt_identically(self):
        flows = [flow(0)] * 12
        det = AnomalyDetector(min_training_windows=40)
        for f in self.windows(40):
            det.detect(flows, f, T0, T0)
        assert det.is_fitted
        restored = AnomalyDetector(min_training_windows=40)
        restored.load_state_dict(roundtrip(det.state_dict()))
        assert restored.is_fitted
        from unishield.detectors.anomaly_detector import anomaly_vector
        for f in self.windows(20, seed=9):
            assert restored.score(anomaly_vector(f)) == det.score(anomaly_vector(f))

    def test_warm_up_buffer_is_restored(self):
        flows = [flow(0)] * 12
        det = AnomalyDetector(min_training_windows=40)
        for f in self.windows(15):
            det.detect(flows, f, T0, T0)
        restored = AnomalyDetector(min_training_windows=40)
        restored.load_state_dict(roundtrip(det.state_dict()))
        assert not restored.is_fitted and len(restored._training) == 15
        for f in self.windows(25, seed=3):
            restored.detect(flows, f, T0, T0)
        assert restored.is_fitted                                        # 15 restored + 25 new

    def test_saved_models_are_not_overwritten_by_snapshots(self):
        saved = AnomalyDetector()
        saved.model_info = {"source": "models/saved/if.joblib"}
        assert saved.state_dict() == {"mode": "saved_model", "source": "models/saved/if.joblib"}
        online = AnomalyDetector()
        online.load_state_dict(saved.state_dict())
        assert not online.is_fitted

    def test_different_features_are_refused(self):
        det = AnomalyDetector()
        state = dict(det.state_dict(), feature_keys=["something", "else"])
        with pytest.raises(ValueError, match="different anomaly features"):
            AnomalyDetector().load_state_dict(state)


class TestReportMemory:
    def test_suppresses_within_the_horizon_unless_severity_rises(self):
        mem = ReportMemory(timedelta(minutes=15))
        assert mem.should_report(("a",), T0, Severity.MEDIUM)
        assert not mem.should_report(("a",), T0 + timedelta(minutes=5), Severity.MEDIUM)
        assert mem.should_report(("a",), T0 + timedelta(minutes=6), Severity.HIGH)
        assert mem.should_report(("a",), T0 + timedelta(minutes=30), Severity.HIGH)

    def test_memory_is_bounded(self):
        mem = ReportMemory(timedelta(minutes=15), limit=100)
        for i in range(1000):
            mem.should_report((i,), T0 + timedelta(minutes=i), Severity.LOW)   # old entries expire
        assert len(mem) <= 100
        busy = ReportMemory(timedelta(days=1), limit=100)
        for i in range(1000):
            busy.should_report((i,), T0 + timedelta(seconds=i), Severity.LOW)  # all live: newest kept
        assert len(busy) <= 101 and (999,) in busy._last

    def test_roundtrip(self):
        mem = ReportMemory(timedelta(minutes=15))
        mem.should_report(("10.0.0.1", "203.0.113.5", None), T0, Severity.HIGH)
        copy = ReportMemory(timedelta(minutes=15))
        copy.load_state_dict(roundtrip(mem.state_dict()))
        assert copy._last == mem._last
        assert not copy.should_report(("10.0.0.1", "203.0.113.5", None), T0 + timedelta(minutes=1), Severity.HIGH)


def test_correlator_dedup_cache_roundtrip():
    correlator = AlertCorrelator()
    result = Pipeline(enable_correlation=True).run(SimulatedReader(build_scenario("port_scan", 1).flows))
    correlator.deduplicate(result.alerts)
    copy = AlertCorrelator()
    copy.load_state_dict(roundtrip(correlator.state_dict()))
    assert copy._dedup_cache == correlator._dedup_cache


def test_pipeline_state_covers_every_stateful_component():
    names = set(Pipeline().state_dict())
    assert names == {
        "extractor:beaconing", "extractor:exfiltration", "detector:beaconing_detector",
        "detector:exfiltration_detector", "detector:encrypted_session_detector",
        "detector:statistical_detector", "detector:anomaly_detector", "correlator",
        "extractor:service_abuse_features", "detector:service_abuse_detector",
    }


def test_api_file_replays_continue_from_the_snapshot(api_client, monkeypatch, tmp_path):
    from unishield.config import reset_config

    client, data_dir = api_client
    state_file = tmp_path / "state" / "pipeline.json"
    monkeypatch.setenv("UNISHIELD_STATE_ENABLED", "true")
    monkeypatch.setenv("UNISHIELD_STATE_FILE", str(state_file))
    reset_config()
    path = save_sample_flows(build_scenario("beacon_30s", 1).flows, data_dir / "flows.jsonl")
    ctx = client.app.state.ctx

    first = client.post("/replay/start", params={"file_path": str(path)}).json()
    assert first["state_persistence"] is True
    ctx.wait(60)
    status = client.get("/replay/status").json()
    assert status["state"]["restore"]["reason"] == "no snapshot (cold start)" and state_file.is_file()

    client.post("/replay/start", params={"file_path": str(path)})
    ctx.wait(60)
    status = client.get("/replay/status").json()
    assert status["state"]["restore"]["restored"] is True
    assert "snapshot file" in next(s for s in client.get("/system/architecture").json()["stages"]
                                   if s["name"] == "state")["detail"]

    assert client.post("/replay/start", params={"file_path": str(path), "state": False}).json()[
        "state_persistence"] is False
    ctx.wait(60)
    client.post("/replay/demo", params={"scenario": "port_scan", "wait": True})
    assert client.get("/replay/status").json()["state"] is None          # synthetic demos never use the snapshot
