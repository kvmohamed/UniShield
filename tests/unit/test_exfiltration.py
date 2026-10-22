"""Unit tests for exfiltration features and detection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from unishield.data.sample_generator import SimulatedReader, generate_scan_traffic
from unishield.detectors.exfiltration_detector import ExfiltrationDetector
from unishield.features.exfiltration import ExfiltrationFeatureExtractor, robust_z
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Severity
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
MB = 1_000_000


def flow(t, src="10.0.2.200", dst="203.0.113.99", up=0, down=0, dport=443, duration=10.0,
         direction=FlowDirection.OUTBOUND, sport=50000):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=sport, destination_port=dport, protocol=ProtocolType.TCP,
                          packet_count=100, byte_count=up + down, orig_bytes=up, resp_bytes=down,
                          duration=duration, conn_state="SF", direction=direction,
                          tcp_flags="ACK,FIN,PSH,SYN")


def detect(flows, ext=None, det=None):
    ext = ext or ExfiltrationFeatureExtractor()
    det = det or ExfiltrationDetector()
    features = ext.extract(flows)
    return det.detect(flows, features, T0, T0 + timedelta(seconds=10))


class TestAttribution:
    def test_downloads_and_server_replies_are_not_uploads(self):
        download = flow(0, up=50_000, down=20 * MB)
        served = flow(1, src="198.51.100.7", dst="10.0.2.10", up=2_000, down=30 * MB,
                      direction=FlowDirection.INBOUND, sport=51000)
        f = ExfiltrationFeatureExtractor().extract([download, served])
        assert f["total_outbound_bytes"] == 50_000
        assert f["total_inbound_bytes"] == 20 * MB + 2_000
        assert f["exfil_candidates"] == []          # below the profiling minimum

    def test_robust_z(self):
        z, median, mad = robust_z(5 * MB, [200_000.0] * 20)
        assert median == 200_000 and mad == 0 and z > 30


class TestRules:
    def test_large_upload_to_rare_destination(self):
        (alert,) = detect([flow(0, up=6 * MB, down=40_000)])
        assert (alert.source_ip, alert.destination_ip) == ("10.0.2.200", "203.0.113.99")
        assert alert.evidence["rules"] == ["volume"] and alert.evidence["rare_destination"]
        assert alert.severity == Severity.HIGH          # MEDIUM by volume, +1 for rare destination
        assert "T1573" in alert.mitre_techniques

    def test_popular_destination_is_not_escalated(self):
        ext = ExfiltrationFeatureExtractor()
        ext.extract([flow(0, src=f"10.0.2.{i}", up=200_000, down=10_000) for i in range(1, 6)])
        (alert,) = detect([flow(5, up=6 * MB, down=40_000)], ext=ext)
        assert alert.severity == Severity.MEDIUM and not alert.evidence["rare_destination"]

    def test_download_dominated_pair_is_ignored(self):
        assert detect([flow(0, up=6 * MB, down=60 * MB)]) == []

    def test_baseline_deviation(self):
        ext, det = ExfiltrationFeatureExtractor(), ExfiltrationDetector()
        for w in range(15):
            batch = [flow(10 * w, dst="198.51.100.200", up=200_000, down=20_000)]
            det.detect(batch, ext.extract(batch), T0, T0)
        spike = [flow(200, dst="198.51.100.200", up=3 * MB, down=50_000)]
        (alert,) = det.detect(spike, ext.extract(spike), T0, T0 + timedelta(seconds=210))
        assert alert.evidence["rules"] == ["baseline"] and alert.evidence["robust_z"] >= 3.5
        assert alert.evidence["baseline_windows"] == 15

    def test_long_session(self):
        (alert,) = detect([flow(0, up=2 * MB, down=100_000, duration=4000)])
        assert alert.evidence["rules"] == ["long_session"]

    def test_unusual_port_is_evidence_not_a_rule(self):
        (alert,) = detect([flow(0, up=6 * MB, down=40_000, dport=4444)])
        assert alert.evidence["unusual_port"] and "T1571" in alert.mitre_techniques
        assert detect([flow(0, up=200_000, down=40_000, dport=4444)]) == []

    def test_scan_traffic_raises_no_exfiltration(self):
        flows = generate_scan_traffic(300, T0, seed=1)
        result = Pipeline(enable_correlation=False).run(SimulatedReader(flows))
        assert not [a for a in result.alerts if a.threat_class.value == "DATA_EXFILTRATION"]

    def test_ongoing_transfer_is_reported_once(self):
        ext, det = ExfiltrationFeatureExtractor(), ExfiltrationDetector()
        alerts = []
        for w in range(12):                      # one minute of 6 MB-per-window uploads
            batch = [flow(5 * w, up=6 * MB, down=40_000)]
            alerts += det.detect(batch, ext.extract(batch), T0, T0 + timedelta(seconds=5 * w + 10))
        assert len(alerts) == 1


def test_destinations_without_recent_uploads_are_dropped():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def up(t, dst):
        return NormalisedFlow(timestamp=t0 + timedelta(seconds=t), source_ip="10.0.2.9", destination_ip=dst,
                              source_port=50000, destination_port=443, protocol=ProtocolType.TCP, packet_count=10,
                              byte_count=210_000, orig_bytes=200_000, resp_bytes=10_000, duration=1.0,
                              conn_state="SF", direction=FlowDirection.OUTBOUND)

    ext = ExfiltrationFeatureExtractor(history_sec=600)
    ext.extract([up(i, f"203.0.113.{i + 1}") for i in range(5)])
    assert len(ext._uploaders) == 5
    ext.extract([up(1000, "203.0.113.99")])
    assert list(ext._uploaders) == ["203.0.113.99"]
