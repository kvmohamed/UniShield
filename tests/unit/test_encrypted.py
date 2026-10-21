"""Unit tests for the encrypted-session module (handshake metadata only)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.sample_generator import SimulatedReader, build_scenario, generate_encrypted_anomaly_traffic
from unishield.detectors.encrypted_detector import EncryptedSessionDetector
from unishield.features.encrypted import EncryptedSessionFeatureExtractor
from unishield.ingest.pcap_reader import PcapReader
from unishield.processing.pipeline import Pipeline
from unishield.processing.sessionizer import Sessionizer
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
BAD_JA3 = "e7d705a3286e19ea42f587b344ee6865"
THRESHOLDS = {"ja3_blocklist": {BAD_JA3: "test-fingerprint"}, "long_session_sec": 1800,
              "low_rate_bytes_per_sec": 200, "realert_after_sec": 900}


def tls(t=0.0, version="TLSv1.3", port=443, ja3=None, duration=1.0, nbytes=5000, src="10.0.2.31",
        dst="198.51.100.77"):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=50000, destination_port=port, protocol=ProtocolType.TCP,
                          byte_count=nbytes, duration=duration, direction=FlowDirection.OUTBOUND,
                          tls_version=version, ja3=ja3)


def run(flows, detector=None, end=10):
    detector = detector or EncryptedSessionDetector(THRESHOLDS)
    features = EncryptedSessionFeatureExtractor(THRESHOLDS).extract(flows)
    return detector.detect(flows, features, T0, T0 + timedelta(seconds=end))


def test_modern_tls_on_443_is_quiet():
    assert run([tls(i) for i in range(20)]) == []


def test_outdated_protocol_is_medium():
    (alert,) = run([tls(0, "TLSv1.0"), tls(1, "TLSv1.0")])
    assert alert.threat_class.value == "ENCRYPTED_SESSION_ANOMALY"
    assert alert.severity.value == "MEDIUM"
    assert alert.evidence["rules"] == ["outdated_protocol"]
    assert alert.evidence["outdated_versions"] == ["TLSv1.0"]
    assert alert.mitre_techniques == ["T1573"]


def test_blocklisted_fingerprint_is_high_and_case_insensitive():
    (alert,) = run([tls(0, ja3=BAD_JA3.upper())])
    assert alert.severity.value == "HIGH"
    assert alert.evidence["blocklisted_ja3"] == {BAD_JA3: "test-fingerprint"}


def test_long_low_rate_session_needs_unusual_port():
    long_flow = dict(duration=3600, nbytes=200_000)
    assert run([tls(0, port=443, **long_flow)]) == []
    (alert,) = run([tls(0, port=4443, **long_flow)])
    assert alert.severity.value == "LOW"
    assert alert.evidence["rules"] == ["long_low_rate_session"]
    assert "T1571" in alert.mitre_techniques


def test_long_busy_session_is_not_low_rate():
    assert run([tls(0, port=4443, duration=3600, nbytes=50_000_000)]) == []


def test_wording_is_cautious():
    (alert,) = run([tls(0, "SSLv3")])
    assert "not decrypted" in alert.evidence["summary"]
    assert "malware" not in str(alert.evidence).lower()


def test_realert_suppression_and_escalation():
    detector = EncryptedSessionDetector(THRESHOLDS)
    assert len(run([tls(0, "TLSv1.0")], detector, end=10)) == 1
    assert run([tls(20, "TLSv1.0")], detector, end=30) == []
    assert detector.suppressed_classes
    assert len(run([tls(40, "TLSv1.0", ja3=BAD_JA3)], detector, end=50)) == 1   # severity rose
    assert len(run([tls(1000, "TLSv1.0")], detector, end=1000)) == 1             # realert window passed


def test_flows_without_tls_metadata_are_ignored():
    plain = tls(0).model_copy(update={"tls_version": None})
    features = EncryptedSessionFeatureExtractor(THRESHOLDS).extract([plain])
    assert features["tls_flow_count"] == 0 and features["tls_candidates"] == []


def test_generator_flows_raise_both_rules():
    flows = generate_encrypted_anomaly_traffic(12, T0, seed=1)
    rules = {r for a in run(flows, end=60) for r in a.evidence["rules"]}
    assert rules == {"outdated_protocol", "long_low_rate_session"}


def test_ja3_survives_pcap_sessionization(sample_capture):
    records = list(Sessionizer().process(PcapReader(sample_capture.path).read()))
    assert any(r.ja3 and len(r.ja3) == 32 for r in records)


@pytest.mark.parametrize("name,expected", [("encrypted_anomaly", True), ("benign_hard", False),
                                           ("beacon_30s", False)])
def test_scenarios_through_the_pipeline(name, expected):
    result = Pipeline().run(SimulatedReader(build_scenario(name, 1).flows))
    found = any(a.threat_class.value == "ENCRYPTED_SESSION_ANOMALY" for a in result.alerts)
    assert found is expected
