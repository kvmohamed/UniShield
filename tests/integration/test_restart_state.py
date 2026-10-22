"""
Restart safety: detections that need history spanning many windows survive a
restart when the pipeline state is snapshotted and restored.

Each test splits one traffic stream at a "restart": the first part runs in one
Pipeline with a state store, the second in a new Pipeline that restores the
snapshot. A cold second Pipeline (no snapshot) is the control.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.sample_generator import (
    C2_SERVER,
    SimulatedReader,
    generate_beacon_traffic,
    generate_normal_traffic,
)
from unishield.processing.pipeline import Pipeline
from unishield.processing.state_store import PipelineStateStore, read_snapshot, write_snapshot
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

pytestmark = pytest.mark.integration
T0 = datetime(2026, 3, 1, tzinfo=timezone.utc)


def run(flows, store=None):
    pipeline = Pipeline(state_store=store)
    return pipeline.run(SimulatedReader(sorted(flows, key=lambda f: f.timestamp)))


def split(flows, cut):
    flows = sorted(flows, key=lambda f: f.timestamp)
    return [f for f in flows if f.timestamp < cut], [f for f in flows if f.timestamp >= cut]


def classes(result, threat):
    return [a for a in result.alerts if a.threat_class.value == threat]


def beacon_stream(connections, seed=5):
    background = generate_normal_traffic(300, T0, gap_ms=(1000, 5000), seed=seed)
    beacon = generate_beacon_traffic(connections, T0 + timedelta(seconds=30), interval_sec=30,
                                     jitter_percent=5, seed=seed)
    return background + beacon, beacon


class TestBeaconAcrossRestart:
    def test_beacon_started_before_a_restart_is_detected_after_it(self, tmp_path):
        flows, beacon = beacon_stream(16)
        first, second = split(flows, beacon[6].timestamp + timedelta(seconds=1))   # 7 check-ins before

        before = run(first, PipelineStateStore(tmp_path / "state.json"))
        assert classes(before, "C2_BEACONING") == []                 # too few check-ins so far
        assert before.summary()["state"]["saves"] >= 1

        restored = run(second, PipelineStateStore(tmp_path / "state.json"))
        cold = run(second)
        beacons = classes(restored, "C2_BEACONING")
        assert {(a.source_ip, a.destination_ip) for a in beacons} == {("10.0.1.50", C2_SERVER)}
        assert beacons[0].evidence["connection_count"] >= 10
        assert classes(cold, "C2_BEACONING") == []                   # without the snapshot it is missed
        status = restored.summary()["state"]["restore"]
        assert status["restored"] and "extractor:beaconing" in status["components"]

    def test_a_reported_beacon_is_not_re_reported_just_because_of_a_restart(self, tmp_path):
        flows, beacon = beacon_stream(22)
        cut = beacon[15].timestamp + timedelta(seconds=1)
        first, second = split(flows, cut)
        path = tmp_path / "state.json"
        assert len(classes(run(first, PipelineStateStore(path)), "C2_BEACONING")) == 1
        snapshot = read_snapshot(path)

        assert classes(run(second, PipelineStateStore(path)), "C2_BEACONING") == []

        # Same snapshot without the detector's re-alert memory: the beacon is reported again.
        components = dict(snapshot["components"])
        del components["detector:beaconing_detector"]
        forgetful = tmp_path / "forgetful.json"
        write_snapshot(forgetful, dict(snapshot, components=components))
        again = run(second, PipelineStateStore(forgetful))
        assert len(classes(again, "C2_BEACONING")) == 1
        assert again.summary()["state"]["restore"]["skipped"]["detector:beaconing_detector"] == "not in snapshot"


class TestUploadBaselineAcrossRestart:
    SRC, DST = "10.0.2.40", "203.0.113.20"

    def upload(self, t, size):
        return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=self.SRC, destination_ip=self.DST,
                              source_port=50000 + int(t) % 10000, destination_port=443,
                              protocol=ProtocolType.TCP, packet_count=200, byte_count=size + 2000,
                              orig_bytes=size, resp_bytes=2000, duration=1.0, conn_state="SF",
                              direction=FlowDirection.OUTBOUND, tcp_flags="ACK,FIN,PSH,SYN")

    def test_baseline_deviation_after_a_restart_is_detected(self, tmp_path):
        """3 MB is below the volume rule (5 MB) but far above the source's learned ~300 kB per window."""
        regular = [self.upload(t, 150_000) for t in range(0, 300, 5)]           # 5 minutes of routine uploads
        after = [self.upload(t, 150_000) for t in range(300, 330, 5)] + [self.upload(331, 3_000_000)]
        path = tmp_path / "state.json"
        run(regular, PipelineStateStore(path))

        exfil = classes(run(after, PipelineStateStore(path)), "DATA_EXFILTRATION")
        assert len(exfil) == 1 and exfil[0].evidence["rules"] == ["baseline"]
        assert exfil[0].evidence["baseline_windows"] >= 10
        assert classes(run(after), "DATA_EXFILTRATION") == []                    # cold: no baseline yet


class TestSnapshotTrust:
    def stream(self):
        return beacon_stream(16)[0]

    def test_tampered_snapshot_is_refused_and_the_run_starts_cold(self, tmp_path):
        path = tmp_path / "state.json"
        flows, beacon = beacon_stream(16)
        first, second = split(flows, beacon[6].timestamp + timedelta(seconds=1))
        run(first, PipelineStateStore(path))
        document = json.loads(path.read_text())
        document["payload"]["components"]["extractor:beaconing"]["pairs"] = []
        path.write_text(json.dumps(document))

        result = run(second, PipelineStateStore(path))
        status = result.summary()["state"]["restore"]
        assert status["restored"] is False and "checksum mismatch" in status["reason"]
        assert classes(result, "C2_BEACONING") == []
        assert read_snapshot(path)                                    # the end of the run wrote a new, valid one

    @pytest.mark.parametrize("change, reason", [
        (lambda d: d.update(version=2), "snapshot version 2"),
        (lambda d: d.update(format="something-else"), "not a UniShield state snapshot"),
        (lambda d: d.pop("payload"), "no payload"),
    ])
    def test_foreign_or_future_snapshots_are_refused(self, tmp_path, change, reason):
        path = tmp_path / "state.json"
        run(self.stream()[:50], PipelineStateStore(path))
        document = json.loads(path.read_text())
        change(document)
        path.write_text(json.dumps(document))
        status = PipelineStateStore(path).restore(Pipeline())
        assert status["restored"] is False and reason in status["reason"]

    def test_unreadable_and_missing_snapshots(self, tmp_path):
        (tmp_path / "junk.json").write_text("{not json")
        assert "unreadable" in PipelineStateStore(tmp_path / "junk.json").restore(Pipeline())["reason"]
        assert PipelineStateStore(tmp_path / "none.json").restore(Pipeline())["reason"] == "no snapshot (cold start)"

    def test_a_failing_component_starts_cold_and_the_rest_is_restored(self, tmp_path):
        path = tmp_path / "state.json"
        run(self.stream()[:200], PipelineStateStore(path))
        payload = read_snapshot(path)
        payload["components"]["detector:statistical_detector"] = {"metrics": ["other"], "history": []}
        payload["components"]["extractor:retired"] = {}
        write_snapshot(path, payload)
        status = PipelineStateStore(path).restore(Pipeline())
        assert status["restored"] and "extractor:beaconing" in status["components"]
        assert status["skipped"]["detector:statistical_detector"].startswith("failed: snapshot baseline")
        assert status["skipped"]["extractor:retired"] == "not in this pipeline"

    def test_snapshots_are_periodic_atomic_and_failures_do_not_stop_the_run(self, tmp_path):
        store = PipelineStateStore(tmp_path / "state.json", snapshot_interval_sec=1e-6)
        result = run(self.stream(), store)
        assert store.saves > 2 and store.save_errors == 0
        assert not list(tmp_path.glob("*.tmp"))
        assert result.summary()["state"]["last_save"]["bytes"] == (tmp_path / "state.json").stat().st_size

        blocked = PipelineStateStore(tmp_path)                        # a directory: every write fails
        result = run(self.stream()[:100], blocked)
        assert blocked.save_errors >= 1 and result.total_windows > 0 and result.errors == 0
