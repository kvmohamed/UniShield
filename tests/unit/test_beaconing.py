"""Unit tests for long-horizon beaconing detection (audit D4)."""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

from unishield.data.sample_generator import SimulatedReader, generate_beacon_traffic
from unishield.detectors.beaconing_detector import BeaconingDetector
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.processing.pipeline import Pipeline
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def conn(t, src="10.0.1.50", dst="198.51.100.42", dport=443, direction=FlowDirection.OUTBOUND, up=200):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=50000, destination_port=dport, protocol=ProtocolType.TCP,
                          packet_count=8, byte_count=up + 200, orig_bytes=up, resp_bytes=200,
                          duration=0.5, conn_state="SF", direction=direction, tcp_flags="ACK,FIN,PSH,SYN")


def run_beacon_only(flows):
    """Pipeline with only beaconing analysis, so the test isolates this detector."""
    pipeline = Pipeline(enable_correlation=False, extractors=[BeaconingFeatureExtractor()],
                        detectors=[BeaconingDetector()])
    return pipeline.run(SimulatedReader(sorted(flows, key=lambda f: f.timestamp)))


def periodic(interval, count, jitter=0.05, seed=1, **kw):
    rng = random.Random(seed)
    t, out = 0.0, []
    for _ in range(count):
        t += interval * (1 + rng.uniform(-jitter, jitter))
        out.append(conn(t, **kw))
    return out


class TestExtractor:
    def test_history_spans_windows_and_overlap_is_not_double_counted(self):
        ext = BeaconingFeatureExtractor()
        flows = periodic(30, 12)
        # feed overlapping "windows": every flow is offered twice
        for i in range(len(flows)):
            features = ext.extract(flows[max(0, i - 1):i + 1])
        (candidate,) = features["beacon_candidates"]
        assert candidate["connection_count"] == 12
        assert 28 < candidate["interval_mean_sec"] < 32
        assert candidate["destination_sources"] == 1 and candidate["uses_tls"]

    def test_inbound_connections_are_not_tracked(self):
        ext = BeaconingFeatureExtractor()
        features = ext.extract(periodic(30, 12, direction=FlowDirection.INBOUND))
        assert features["beacon_candidates"] == [] and features["tracked_pairs"] == 0

    def test_old_connections_leave_the_history(self):
        ext = BeaconingFeatureExtractor(history_sec=300)
        ext.extract(periodic(60, 12))
        features = ext.extract([conn(5000)])
        assert features["beacon_candidates"] == []

    def test_number_of_tracked_pairs_is_bounded(self):
        ext = BeaconingFeatureExtractor(max_pairs=10)
        ext.extract([conn(i, dst=f"203.0.113.{i + 1}") for i in range(50)])
        assert ext.extract([])["tracked_pairs"] == 10


class TestDetection:
    def test_30_and_60_second_beacons_are_detected(self):
        for interval, count in ((30, 15), (60, 12)):
            alerts = run_beacon_only(periodic(interval, count)).alerts
            assert [(a.threat_class.value, a.source_ip, a.destination_ip) for a in alerts] == \
                [("C2_BEACONING", "10.0.1.50", "198.51.100.42")]
            assert "T1573" in alerts[0].mitre_techniques

    def test_sub_second_regular_traffic_is_not_a_beacon(self):
        """Scan probes / page loads are perfectly regular but far faster than a beacon."""
        assert run_beacon_only(periodic(0.2, 60, jitter=0.0)).alerts == []

    def test_destination_polled_by_many_hosts_is_not_a_beacon(self):
        flows = [f for i in range(8) for f in periodic(60, 12, seed=i, src=f"10.0.1.{i + 10}")]
        assert run_beacon_only(flows).alerts == []

    def test_irregular_connections_are_not_a_beacon(self):
        rng = random.Random(3)
        t, flows = 0.0, []
        for _ in range(20):
            t += rng.uniform(5, 300)
            flows.append(conn(t))
        assert run_beacon_only(flows).alerts == []

    def test_ongoing_beacon_is_reported_once_until_realert_interval(self):
        alerts = run_beacon_only(periodic(30, 50, jitter=0.02)).alerts   # 25 minutes of beaconing
        assert len(alerts) == 2                                           # first report + one after 900 s
        gap = (alerts[1].window_end - alerts[0].window_end).total_seconds()
        assert gap >= 900

    def test_generator_beacons_detected_with_background(self):
        flows = generate_beacon_traffic(20, T0, interval_sec=45, jitter_percent=5, seed=4)
        alerts = run_beacon_only(flows).alerts
        assert alerts and alerts[0].evidence["connection_count"] >= 10
