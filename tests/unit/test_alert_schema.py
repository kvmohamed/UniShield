"""
UniShield — Unit Tests for Alert Schema

Tests alert validation, confidence bounds, severity levels,
MITRE technique format, and alert summary generation.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from unishield.schemas.alert import (
    Alert,
    AlertSummary,
    Severity,
    SourceType,
    ThreatClass,
)


class TestAlertCreation:
    """Test valid alert construction."""

    def test_minimal_alert(self):
        """An alert with all required fields should be valid."""
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.PORT_SCAN,
            severity=Severity.HIGH,
            confidence=0.92,
            detector_name="scan_rule_detector",
            evidence={"unique_destination_ports": 85},
            mitre_techniques=["T1046"],
        )
        assert alert.alert_id.startswith("US-")
        assert alert.threat_class == ThreatClass.PORT_SCAN
        assert alert.severity == Severity.HIGH
        assert alert.confidence == 0.92
        assert "T1046" in alert.mitre_techniques

    def test_all_threat_classes(self):
        """All defined threat classes should be valid."""
        now = datetime.utcnow()
        for tc in ThreatClass:
            alert = Alert(
                window_start=now - timedelta(seconds=10),
                window_end=now,
                threat_class=tc,
                severity=Severity.MEDIUM,
                confidence=0.5,
                detector_name="test_detector",
            )
            assert alert.threat_class == tc

    def test_all_severity_levels(self):
        """All severity levels should be valid."""
        now = datetime.utcnow()
        for sev in Severity:
            alert = Alert(
                window_start=now - timedelta(seconds=10),
                window_end=now,
                threat_class=ThreatClass.STATISTICAL_ANOMALY,
                severity=sev,
                confidence=0.5,
                detector_name="test_detector",
            )
            assert alert.severity == sev

    def test_ddos_alert_with_evidence(self):
        """A DDoS alert should include relevant evidence."""
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.DDOS_VOLUMETRIC,
            severity=Severity.CRITICAL,
            confidence=0.95,
            detector_name="ddos_rule_detector",
            evidence={
                "packets_per_second": 50000,
                "bytes_per_second": 200000000,
                "syn_ack_imbalance": 8.5,
                "unique_source_count": 1200,
            },
            mitre_techniques=["T1498"],
        )
        assert alert.evidence["packets_per_second"] == 50000
        assert alert.confidence == 0.95


class TestAlertConfidence:
    """Test confidence validation (must be [0, 1])."""

    def test_confidence_zero(self):
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.PORT_SCAN,
            severity=Severity.LOW,
            confidence=0.0,
            detector_name="test",
        )
        assert alert.confidence == 0.0

    def test_confidence_one(self):
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.PORT_SCAN,
            severity=Severity.LOW,
            confidence=1.0,
            detector_name="test",
        )
        assert alert.confidence == 1.0

    def test_confidence_above_one_clamped(self):
        """Confidence > 1.0 should be clamped to 1.0 by the validator."""
        now = datetime.utcnow()
        # Pydantic ge/le will reject > 1.0 before our validator runs
        with pytest.raises(Exception):
            Alert(
                window_start=now - timedelta(seconds=10),
                window_end=now,
                threat_class=ThreatClass.PORT_SCAN,
                severity=Severity.LOW,
                confidence=1.5,
                detector_name="test",
            )

    def test_confidence_negative_rejected(self):
        now = datetime.utcnow()
        with pytest.raises(Exception):
            Alert(
                window_start=now - timedelta(seconds=10),
                window_end=now,
                threat_class=ThreatClass.PORT_SCAN,
                severity=Severity.LOW,
                confidence=-0.1,
                detector_name="test",
            )


class TestMitreTechniqueValidation:
    """Test MITRE ATT&CK technique ID validation."""

    def test_valid_technique_id(self):
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.PORT_SCAN,
            severity=Severity.HIGH,
            confidence=0.9,
            detector_name="test",
            mitre_techniques=["T1046"],
        )
        assert alert.mitre_techniques == ["T1046"]

    def test_valid_subtechnique_id(self):
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.C2_BEACONING,
            severity=Severity.HIGH,
            confidence=0.85,
            detector_name="test",
            mitre_techniques=["T1071", "T1071.001"],
        )
        assert len(alert.mitre_techniques) == 2

    def test_invalid_technique_id_rejected(self):
        now = datetime.utcnow()
        with pytest.raises(Exception):
            Alert(
                window_start=now - timedelta(seconds=10),
                window_end=now,
                threat_class=ThreatClass.PORT_SCAN,
                severity=Severity.HIGH,
                confidence=0.9,
                detector_name="test",
                mitre_techniques=["INVALID"],
            )

    def test_empty_mitre_techniques_valid(self):
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.STATISTICAL_ANOMALY,
            severity=Severity.LOW,
            confidence=0.3,
            detector_name="test",
            mitre_techniques=[],
        )
        assert alert.mitre_techniques == []


class TestAlertIds:
    """Test alert ID generation."""

    def test_alert_id_prefix(self):
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            threat_class=ThreatClass.PORT_SCAN,
            severity=Severity.HIGH,
            confidence=0.9,
            detector_name="test",
        )
        assert alert.alert_id.startswith("US-")

    def test_unique_alert_ids(self):
        now = datetime.utcnow()
        ids = set()
        for _ in range(100):
            alert = Alert(
                window_start=now - timedelta(seconds=10),
                window_end=now,
                threat_class=ThreatClass.PORT_SCAN,
                severity=Severity.HIGH,
                confidence=0.9,
                detector_name="test",
            )
            ids.add(alert.alert_id)
        assert len(ids) == 100, "Alert IDs should be unique"


class TestAlertSerialisation:
    """Test JSON serialisation."""

    def test_json_round_trip(self):
        now = datetime.utcnow()
        alert = Alert(
            window_start=now - timedelta(seconds=10),
            window_end=now,
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            threat_class=ThreatClass.SYN_FLOOD,
            severity=Severity.CRITICAL,
            confidence=0.98,
            detector_name="ddos_rule_detector",
            evidence={"syn_rate": 50000},
            mitre_techniques=["T1498"],
            detection_latency_ms=120.5,
            source_type=SourceType.PCAP_REPLAY,
        )
        json_str = alert.model_dump_json()
        restored = Alert.model_validate_json(json_str)
        assert restored.threat_class == ThreatClass.SYN_FLOOD
        assert restored.confidence == 0.98
        assert restored.evidence["syn_rate"] == 50000


class TestAlertSummary:
    """Test alert summary aggregation model."""

    def test_empty_summary(self):
        summary = AlertSummary()
        assert summary.total_alerts == 0
        assert summary.avg_confidence == 0.0

    def test_summary_with_data(self):
        summary = AlertSummary(
            total_alerts=42,
            by_threat_class={"PORT_SCAN": 20, "DDOS_VOLUMETRIC": 22},
            by_severity={"HIGH": 30, "MEDIUM": 12},
            avg_confidence=0.85,
        )
        assert summary.total_alerts == 42
        assert summary.by_threat_class["PORT_SCAN"] == 20
