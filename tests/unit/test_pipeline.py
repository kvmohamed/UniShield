"""
Tests for the processing pipeline, feature extractors and detectors.
(Window tests: test_window.py; DDoS/scan rules: test_ddos.py, test_scan.py.)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


from unishield.data.sample_generator import (
    SimulatedReader,
    generate_beacon_traffic,
    generate_ddos_traffic,
    generate_exfil_traffic,
    generate_mixed_scenario,
    generate_normal_traffic,
    generate_scan_traffic,
)
from unishield.detectors.beaconing_detector import BeaconingDetector
from unishield.detectors.ddos_detector import DDoSDetector
from unishield.detectors.exfiltration_detector import ExfiltrationDetector
from unishield.detectors.scan_detector import ScanDetector
from unishield.features.beaconing import BeaconingFeatureExtractor
from unishield.features.exfiltration import ExfiltrationFeatureExtractor
from unishield.features.scan import ScanFeatureExtractor
from unishield.features.volume import VolumeFeatureExtractor
from unishield.processing.pipeline import Pipeline
from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)


# ===================================================================
# Helpers
# ===================================================================

def _make_flow(
    timestamp: datetime,
    src_ip: str = "10.0.1.1",
    dst_ip: str = "203.0.113.1",
    src_port: int = 50000,
    dst_port: int = 80,
    protocol: ProtocolType = ProtocolType.TCP,
    packet_count: int = 10,
    byte_count: int = 1000,
    tcp_flags: str | None = "SYN,ACK",
    direction: FlowDirection = FlowDirection.OUTBOUND,
    duration: float | None = 1.0,
) -> NormalisedFlow:
    return NormalisedFlow(
        timestamp=timestamp,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=protocol,
        packet_count=packet_count,
        byte_count=byte_count,
        tcp_flags=tcp_flags,
        direction=direction,
        duration=duration,
        source=InputSource.SIMULATED,
    )


# ===================================================================
# Feature Extractor Tests
# ===================================================================

class TestVolumeFeatureExtractor:
    def test_basic_extraction(self):
        ext = VolumeFeatureExtractor()
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flows = [
            _make_flow(t0 + timedelta(seconds=i), packet_count=10, byte_count=1000)
            for i in range(5)
        ]
        features = ext.extract(flows)

        assert features["total_packets"] == 50
        assert features["total_bytes"] == 5000
        assert features["total_flows"] == 5
        assert features["packets_per_second"] > 0
        assert ext.validate_features(features)

    def test_empty_flows(self):
        ext = VolumeFeatureExtractor()
        features = ext.extract([])
        assert features["total_packets"] == 0.0

    def test_protocol_ratios(self):
        ext = VolumeFeatureExtractor()
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flows = [
            _make_flow(t0, protocol=ProtocolType.TCP),
            _make_flow(t0 + timedelta(seconds=1), protocol=ProtocolType.UDP),
            _make_flow(t0 + timedelta(seconds=2), protocol=ProtocolType.TCP),
        ]
        features = ext.extract(flows)
        assert abs(features["tcp_ratio"] - 2/3) < 0.01
        assert abs(features["udp_ratio"] - 1/3) < 0.01

    def test_syn_counting(self):
        ext = VolumeFeatureExtractor()
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        flows = [
            _make_flow(t0, tcp_flags="SYN"),
            _make_flow(t0 + timedelta(seconds=1), tcp_flags="SYN"),
            _make_flow(t0 + timedelta(seconds=2), tcp_flags="SYN,ACK"),
        ]
        features = ext.extract(flows)
        assert features["syn_count"] == 2
        assert features["syn_ack_count"] == 1


class TestScanFeatureExtractor:
    def test_scan_detection_features(self):
        ext = ScanFeatureExtractor()
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # Simulate a scanner hitting many ports
        flows = [
            _make_flow(
                t0 + timedelta(seconds=i * 0.1),
                src_ip="198.18.0.1",
                dst_ip="10.0.1.100",
                dst_port=i + 1,
                tcp_flags="SYN",
                packet_count=1,
                byte_count=40,
            )
            for i in range(50)
        ]
        features = ext.extract(flows)
        assert features["top_scanner_port_count"] == 50
        assert features["top_scanner_ip"] == "198.18.0.1"

    def test_burst_detection(self):
        ext = ScanFeatureExtractor()
        t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        # 30 connections in 1 second
        flows = [
            _make_flow(t0 + timedelta(milliseconds=i * 30), dst_port=i + 1)
            for i in range(30)
        ]
        features = ext.extract(flows)
        assert features["burst_connections"] >= 25  # Most should be in one burst


class TestBeaconingFeatureExtractor:
    def test_regular_beacon(self):
        ext = BeaconingFeatureExtractor(min_connections=5)
        # Generate very regular intervals (60s ± 1%)
        flows = generate_beacon_traffic(
            beacon_count=20,
            interval_sec=60.0,
            jitter_percent=1.0,
        )
        features = ext.extract(flows)
        assert features["candidate_beacon_pairs"] >= 1
        assert features["top_beacon_interval_cv"] < 0.1  # Very regular

    def test_no_beacon_in_random_traffic(self):
        ext = BeaconingFeatureExtractor(min_connections=10)
        flows = generate_normal_traffic(count=50)
        features = ext.extract(flows)
        # May find candidates but CV should be high
        if features["candidate_beacon_pairs"] > 0:
            assert features["top_beacon_interval_cv"] > 0.2


class TestExfiltrationFeatureExtractor:
    def test_exfil_features(self):
        ext = ExfiltrationFeatureExtractor()
        flows = generate_exfil_traffic(count=20)
        features = ext.extract(flows)
        assert features["total_outbound_bytes"] > 0
        assert features["max_session_bytes"] > 0


# ===================================================================
# Detector Tests
# ===================================================================

class TestDDoSDetector:
    def test_detects_volumetric_ddos(self):
        detector = DDoSDetector(thresholds={
            "packets_per_second": 100,
            "bytes_per_second": 50000,
            "syn_rate_threshold": 50,
            "syn_ack_imbalance_ratio": 3.0,
            "udp_flood_pps": 80,
            "severity_levels": {
                "critical": {"packets_per_second": 500},
                "high": {"packets_per_second": 200},
                "medium": {"packets_per_second": 100},
            },
        })
        ext = VolumeFeatureExtractor()

        flows = generate_ddos_traffic(count=500)
        features = ext.extract(flows)

        t0 = flows[0].timestamp
        t1 = flows[-1].timestamp
        alerts = detector.detect(flows, features, t0, t1)

        assert len(alerts) > 0
        threat_classes = {a.threat_class.value for a in alerts}
        assert "DDOS_VOLUMETRIC" in threat_classes or "SYN_FLOOD" in threat_classes

    def test_no_false_alarm_on_normal(self):
        detector = DDoSDetector()  # Uses default thresholds
        ext = VolumeFeatureExtractor()

        flows = generate_normal_traffic(count=50)
        features = ext.extract(flows)

        t0 = flows[0].timestamp
        t1 = flows[-1].timestamp
        alerts = detector.detect(flows, features, t0, t1)

        # With default thresholds (10000 pps), normal traffic shouldn't trigger
        ddos_alerts = [a for a in alerts if a.threat_class.value in ("DDOS_VOLUMETRIC", "SYN_FLOOD", "UDP_FLOOD")]
        assert len(ddos_alerts) == 0


class TestScanDetector:
    def test_detects_port_scan(self):
        detector = ScanDetector(thresholds={
            "unique_dest_ports": 25,
            "unique_dest_hosts": 10,
            "failed_connection_ratio": 0.7,
            "fanout_score": 0.8,
            "horizontal_scan_hosts": 20,
            "burst_connections": 30,
            "severity_levels": {
                "critical": {"unique_dest_ports": 100, "unique_dest_hosts": 50},
                "high": {"unique_dest_ports": 50, "unique_dest_hosts": 25},
                "medium": {"unique_dest_ports": 25, "unique_dest_hosts": 10},
            },
        })
        ext = ScanFeatureExtractor()

        flows = generate_scan_traffic(count=100)
        features = ext.extract(flows)

        t0 = flows[0].timestamp
        t1 = flows[-1].timestamp
        alerts = detector.detect(flows, features, t0, t1)

        assert len(alerts) > 0
        threat_classes = {a.threat_class.value for a in alerts}
        assert "PORT_SCAN" in threat_classes or "HOST_SCAN" in threat_classes


class TestBeaconingDetector:
    def test_detects_beaconing(self):
        detector = BeaconingDetector(thresholds={
            "regularity_cv_threshold": 0.3,
            "periodicity_score": 0.5,
            "packet_size_regularity": 0.5,
            "min_connections": 10,
            "severity_levels": {},
        })
        ext = BeaconingFeatureExtractor(min_connections=5)

        flows = generate_beacon_traffic(beacon_count=30, interval_sec=60, jitter_percent=2)
        features = ext.extract(flows)

        t0 = flows[0].timestamp
        t1 = flows[-1].timestamp
        alerts = detector.detect(flows, features, t0, t1)

        assert len(alerts) > 0
        assert alerts[0].threat_class.value == "C2_BEACONING"


class TestExfiltrationDetector:
    def test_detects_exfiltration(self):
        detector = ExfiltrationDetector(thresholds={
            "outbound_inbound_byte_ratio": 3.0,
            "unusual_outbound_volume_mb": 5,
            "port_rarity_threshold": 0.5,
            "long_session_duration_sec": 3600,
            "severity_levels": {
                "critical": {"outbound_inbound_byte_ratio": 20, "unusual_outbound_volume_mb": 500},
                "high": {"outbound_inbound_byte_ratio": 10, "unusual_outbound_volume_mb": 200},
                "medium": {"outbound_inbound_byte_ratio": 3, "unusual_outbound_volume_mb": 5},
            },
        })
        ext = ExfiltrationFeatureExtractor()

        flows = generate_exfil_traffic(count=30)
        features = ext.extract(flows)

        t0 = flows[0].timestamp
        t1 = flows[-1].timestamp
        alerts = detector.detect(flows, features, t0, t1)

        assert len(alerts) > 0
        assert any(a.threat_class.value == "DATA_EXFILTRATION" for a in alerts)


# ===================================================================
# Pipeline Integration Tests
# ===================================================================

class TestPipeline:
    def test_pipeline_runs_on_mixed_scenario(self):
        """Full integration: pipeline processes mixed traffic and produces alerts."""
        flows = generate_mixed_scenario(
            normal_count=100,
            ddos_count=200,
            scan_count=80,
            beacon_count=25,
            exfil_count=30,
        )
        reader = SimulatedReader(flows)

        pipeline = Pipeline(
            window_size_sec=10,
            slide_interval_sec=5,
        )
        result = pipeline.run(reader)

        # Basic checks
        assert result.total_records == len(flows)
        assert result.total_windows > 0
        assert result.duration_seconds > 0
        assert result.records_per_second > 0
        assert result.errors == 0

        # Should produce alerts for the embedded attacks
        assert result.total_alerts > 0
        assert len(result.alerts) == result.total_alerts

        # Check that multiple threat classes are detected
        threat_classes = {a.threat_class.value for a in result.alerts}
        assert len(threat_classes) >= 2, f"Expected 2+ threat classes, got: {threat_classes}"

    def test_pipeline_on_normal_traffic(self):
        """Normal traffic should produce few or no alerts with default thresholds."""
        flows = generate_normal_traffic(count=200)
        reader = SimulatedReader(flows)

        pipeline = Pipeline(window_size_sec=10, slide_interval_sec=5)
        result = pipeline.run(reader)

        assert result.total_records == 200
        assert result.errors == 0
        # May still get some alerts but should be much fewer than attack scenario

    def test_pipeline_result_summary(self):
        """Pipeline result summary should contain all expected fields."""
        flows = generate_normal_traffic(count=50)
        reader = SimulatedReader(flows)

        pipeline = Pipeline(window_size_sec=5, slide_interval_sec=2)
        result = pipeline.run(reader)

        summary = result.summary()
        assert "total_records" in summary
        assert "total_windows" in summary
        assert "total_alerts" in summary
        assert "records_per_second" in summary
        assert "latency_avg_ms" in summary
        assert "latency_p50_ms" in summary
        assert "latency_p95_ms" in summary

    def test_pipeline_metrics(self):
        """Pipeline should report metrics."""
        pipeline = Pipeline()
        metrics = pipeline.get_metrics()
        assert metrics.window_size_sec > 0
        assert {d.name for d in pipeline.detectors} == {
            "ddos_detector",
            "scan_detector",
            "beaconing_detector",
            "exfiltration_detector",
            "dns_detector",
            "encrypted_session_detector",
            "intel_detector",
            "statistical_detector",
            "anomaly_detector",
        }
        assert metrics.detectors_loaded == len(pipeline.detectors)
