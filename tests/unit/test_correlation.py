"""Unit tests for event-time deduplication, incidents, severity and MITRE mapping (audit D3)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

import pytest

from unishield.correlation import severity as sev
from unishield.correlation.correlator import AlertCorrelator
from unishield.correlation.mitre_mapping import MITRE_TECHNIQUES, techniques_for
from unishield.schemas.alert import Alert, Severity, ThreatClass

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def alert(end_sec, cls=ThreatClass.PORT_SCAN, src="198.51.100.66", dst=None, severity=Severity.MEDIUM,
          detector="scan_detector"):
    end = T0 + timedelta(seconds=end_sec)
    return Alert(window_start=end - timedelta(seconds=10), window_end=end, source_ip=src, destination_ip=dst,
                 threat_class=cls, severity=severity, confidence=0.8, detector_name=detector)


class TestDeduplication:
    def test_uses_traffic_time_not_creation_time(self):
        """Audit D3: three episodes 20 minutes apart, created within milliseconds, are all kept."""
        c = AlertCorrelator(dedup_window_sec=60)
        kept = c.deduplicate([alert(0), alert(1200), alert(2400)])
        assert len(kept) == 3 and c.suppressed_count == 0

    def test_repeats_within_the_window_are_suppressed(self):
        c = AlertCorrelator(dedup_window_sec=60)
        kept = c.deduplicate([alert(10), alert(15), alert(20), alert(75)])
        assert [a.window_end for a in kept] == [T0 + timedelta(seconds=10), T0 + timedelta(seconds=75)]

    def test_destination_is_part_of_the_key(self):
        c = AlertCorrelator()
        floods = [alert(10, ThreatClass.SYN_FLOOD, src=None, dst="10.0.0.5", detector="ddos_detector"),
                  alert(10, ThreatClass.SYN_FLOOD, src=None, dst="10.0.0.6", detector="ddos_detector")]
        assert len(c.deduplicate(floods)) == 2


class TestIncidents:
    def test_sourceless_alerts_group_by_destination(self):
        c = AlertCorrelator(min_alerts_for_incident=2)
        alerts = [alert(10, ThreatClass.SYN_FLOOD, src=None, dst="10.0.1.100", detector="ddos_detector"),
                  alert(15, ThreatClass.UDP_FLOOD, src=None, dst="10.0.1.100", detector="ddos_detector")]
        (incident,) = c.correlate(alerts)
        assert incident["entity"] == "10.0.1.100" and incident["source_ip"] is None
        assert incident["threat_classes"] == ["SYN_FLOOD", "UDP_FLOOD"]
        assert incident["severity"] == "HIGH"           # two classes escalate MEDIUM by one level

    def test_three_classes_make_a_critical_multi_vector_incident(self):
        c = AlertCorrelator()
        alerts = [alert(10, ThreatClass.PORT_SCAN), alert(20, ThreatClass.HOST_SCAN),
                  alert(30, ThreatClass.RECONNAISSANCE)]
        (incident,) = c.correlate(alerts)
        assert incident["severity"] == "CRITICAL" and incident["is_multi_vector"]

    def test_long_gap_splits_incidents(self):
        c = AlertCorrelator(correlation_window_sec=300)
        alerts = [alert(10), alert(20), alert(1000), alert(1010)]
        assert len(c.correlate(alerts)) == 2

    def test_single_alert_is_not_an_incident(self):
        assert AlertCorrelator(min_alerts_for_incident=2).correlate([alert(10)]) == []


class TestSeverity:
    def test_order_and_escalation(self):
        assert sev.max_severity([Severity.LOW, Severity.HIGH, Severity.MEDIUM]) == Severity.HIGH
        assert sev.escalate(Severity.HIGH) == Severity.CRITICAL
        assert sev.escalate(Severity.CRITICAL) == Severity.CRITICAL
        assert sev.at_least(Severity.LOW, Severity.MEDIUM) == Severity.MEDIUM

    def test_from_levels(self):
        levels = {"critical": {"x": 100}, "high": {"x": 50}, "medium": {"x": 25}}
        assert [sev.from_levels(v, levels, "x") for v in (10, 25, 60, 150)] == \
            [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class TestMitreMapping:
    def test_every_threat_class_is_mapped_with_valid_ids(self):
        assert set(MITRE_TECHNIQUES) == set(ThreatClass)
        pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
        assert all(pattern.match(t) for ts in MITRE_TECHNIQUES.values() for t in ts)

    def test_extras_are_appended_once(self):
        assert techniques_for(ThreatClass.C2_BEACONING, "T1573", "T1573") == ["T1071", "T1573"]

    @pytest.mark.parametrize("cls,expected", [
        (ThreatClass.SYN_FLOOD, "T1499.001"), (ThreatClass.DGA_DETECTED, "T1568.002"),
        (ThreatClass.HOST_SCAN, "T1595.001"), (ThreatClass.DNS_TUNNELLING, "T1071.004"),
    ])
    def test_key_mappings(self, cls, expected):
        assert expected in techniques_for(cls)
