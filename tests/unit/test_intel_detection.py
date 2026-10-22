"""Threat-intel matches in detection: INTEL_MATCH alerts, enrichment of other alerts, JA3 feed."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from unishield.correlation.mitre_mapping import MITRE_TECHNIQUES
from unishield.data.sample_generator import C2_SERVER, SimulatedReader, build_scenario
from unishield.detectors.intel_detector import IntelDetector
from unishield.features.intel import IntelFeatureExtractor
from unishield.intel.enrich import enrich_alerts
from unishield.intel.matcher import IntelEntry, IntelMatcher, hash_ip
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Alert, Severity, ThreatClass
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
BAD_JA3 = "e7d705a3286e19ea42f587b344ee6865"
THRESHOLDS = {"outbound_severity": "HIGH", "dns_severity": "HIGH", "inbound_severity": "MEDIUM",
              "other_severity": "MEDIUM", "base_confidence": 0.7, "realert_after_sec": 900}


def matcher(*extra: IntelEntry) -> IntelMatcher:
    return IntelMatcher([
        IntelEntry("feodo", "ip", "198.51.100.42", "QakBot C2", techniques=("T1071",)),
        IntelEntry("hosting", "cidr", "203.0.113.0/24", "bulletproof hosting"),
        IntelEntry("phish", "domain", "bad.example", "phishing kit"),
        *extra,
    ])


def flow(t=0.0, src="10.0.1.50", dst="198.51.100.42", direction=FlowDirection.OUTBOUND, port=443, query=None,
         nbytes=500):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=50000, destination_port=port,
                          protocol=ProtocolType.UDP if query else ProtocolType.TCP, byte_count=nbytes,
                          direction=direction, dns_query=query)


def detect(flows, m=None, detector=None, end=10):
    features = IntelFeatureExtractor(m or matcher()).extract(flows)
    detector = detector or IntelDetector(THRESHOLDS)
    return detector.detect(flows, features, T0, T0 + timedelta(seconds=end)), features


class TestFeatures:
    def test_groups_destination_source_and_dns_matches(self):
        flows = [flow(0), flow(1), flow(2, src="10.0.1.51"),                                   # 2 hosts → C2
                 flow(3, src="203.0.113.7", dst="10.0.1.60", direction=FlowDirection.INBOUND, port=22),
                 flow(4, src="203.0.113.7", dst="10.0.1.61", direction=FlowDirection.INBOUND, port=22),
                 flow(5, dst="10.0.1.53", direction=FlowDirection.INTERNAL, port=53, query="x1.bad.example"),
                 flow(6, dst="10.0.1.53", direction=FlowDirection.INTERNAL, port=53, query="x2.bad.example"),
                 flow(7, src="10.0.1.70", dst="192.0.2.10")]                                    # unlisted
        features = IntelFeatureExtractor(matcher()).extract(flows)
        by_key = {(m["field"], m["observed"], tuple(m["peers"])): m for m in features["intel_matches"]}
        assert features["intel_match_count"] == 4
        c2 = by_key[("destination_ip", "198.51.100.42", ("10.0.1.50",))]
        assert c2["flows"] == 2 and c2["direction"] == "outbound" and c2["techniques"] == ["T1071"]
        assert c2["intel_matches"][0]["source"] == "feodo"
        inbound = by_key[("source_ip", "203.0.113.7", ("10.0.1.60", "10.0.1.61"))]
        assert inbound["peer_count"] == 2 and inbound["destination_ports"] == [22]
        assert inbound["intel_matches"][0]["indicator"] == "203.0.113.0/24"
        dns = by_key[("dns_query", "bad.example", ("10.0.1.50",))]
        assert dns["query_names"] == ["x1.bad.example", "x2.bad.example"]

    def test_empty_matcher_does_no_work(self):
        assert IntelFeatureExtractor().extract([flow(0)]) == {"intel_match_count": 0, "intel_matches": []}


class TestDetector:
    def test_severity_by_what_was_seen(self):
        alerts, _ = detect([
            flow(0),
            flow(1, src="203.0.113.7", dst="10.0.1.60", direction=FlowDirection.INBOUND, port=22),
            flow(2, dst="10.0.1.53", direction=FlowDirection.INTERNAL, port=53, query="c2.bad.example"),
        ])
        by_field = {a.evidence["matched_field"]: a for a in alerts}
        out, inbound, dns = by_field["destination_ip"], by_field["source_ip"], by_field["dns_query"]
        assert all(a.threat_class == ThreatClass.INTEL_MATCH for a in alerts)
        assert (out.severity, out.source_ip, out.destination_ip) == (Severity.HIGH, "10.0.1.50", "198.51.100.42")
        assert out.mitre_techniques == ["T1071"] and out.confidence == 0.7
        assert out.evidence["intel_matches"][0]["label"] == "QakBot C2"
        assert (inbound.severity, inbound.source_ip, inbound.destination_ip) == \
            (Severity.MEDIUM, "203.0.113.7", "10.0.1.60")
        assert (dns.severity, dns.source_ip, dns.destination_ip) == (Severity.HIGH, "10.0.1.50", None)
        assert dns.evidence["query_names"] == ["c2.bad.example"]

    def test_indicator_severity_overrides_and_more_lists_raise_confidence(self):
        m = matcher(IntelEntry("partner", "ip", "198.51.100.42", "C2", severity="CRITICAL"))
        (alert,), _ = detect([flow(0)], m)
        assert alert.severity == Severity.CRITICAL
        assert alert.confidence == pytest.approx(0.8)
        assert alert.evidence["sources"] == ["feodo", "partner"]

    def test_repeats_are_suppressed_until_realert(self):
        detector = IntelDetector(THRESHOLDS)
        first, _ = detect([flow(0)], detector=detector, end=10)
        again, _ = detect([flow(15)], detector=detector, end=20)
        later, _ = detect([flow(1000)], detector=detector, end=1010)
        assert len(first) == 1 and again == [] and len(later) == 1
        assert ThreatClass.INTEL_MATCH not in detector.suppressed_classes     # last call reported

    def test_every_class_including_intel_is_mapped(self):
        assert ThreatClass.INTEL_MATCH in MITRE_TECHNIQUES and MITRE_TECHNIQUES[ThreatClass.INTEL_MATCH] == ()


class TestEnrichment:
    def alert(self, cls=ThreatClass.C2_BEACONING, src="10.0.1.50", dst="198.51.100.42", severity=Severity.MEDIUM,
              evidence=None):
        return Alert(window_start=T0, window_end=T0 + timedelta(seconds=10), source_ip=src, destination_ip=dst,
                     threat_class=cls, severity=severity, confidence=0.8, detector_name="beaconing_detector",
                     evidence=evidence or {}, mitre_techniques=["T1071"])

    def test_listed_address_adds_evidence_techniques_and_one_severity_level(self):
        a = self.alert()
        assert enrich_alerts([a], matcher(IntelEntry("x", "ip", "198.51.100.42", "C2", techniques=("T1573",)))) == 1
        assert a.severity == Severity.HIGH and a.evidence["intel_escalated_from"] == "MEDIUM"
        assert {m["source"] for m in a.evidence["intel_matches"]} == {"feodo", "x"}
        assert a.mitre_techniques == ["T1071", "T1573"]

    def test_escalation_can_be_disabled_and_unlisted_alerts_are_untouched(self):
        a, b = self.alert(), self.alert(dst="192.0.2.1")
        enrich_alerts([a, b], matcher(), escalate=False)
        assert a.severity == Severity.MEDIUM and "intel_matches" in a.evidence
        assert "intel_matches" not in b.evidence

    def test_dns_alert_domains_and_ja3_evidence(self):
        tunnel = self.alert(ThreatClass.DNS_TUNNELLING, dst=None, evidence={"base_domain": "t.bad.example"})
        tls = self.alert(ThreatClass.ENCRYPTED_SESSION_ANOMALY, dst="192.0.2.1", severity=Severity.HIGH,
                         evidence={"blocklisted_ja3": {BAD_JA3: "intel"}})
        m = matcher(IntelEntry("sslbl", "ja3", BAD_JA3, "Tofsee"))
        enrich_alerts([tunnel, tls], m)
        assert tunnel.evidence["intel_matches"][0]["indicator"] == "bad.example" and tunnel.severity == Severity.HIGH
        assert tls.evidence["intel_matches"][0]["kind"] == "ja3"
        assert tls.severity == Severity.HIGH                      # JA3 already rated by the detector

    def test_intel_match_alerts_are_not_enriched_again(self):
        a = self.alert(ThreatClass.INTEL_MATCH)
        assert enrich_alerts([a], matcher()) == 0 and a.severity == Severity.MEDIUM


class TestPipeline:
    def test_beacon_to_listed_c2_raises_intel_match_and_escalates_the_beacon(self):
        scenario = build_scenario("beacon_30s", 1)
        c2_only = IntelMatcher([IntelEntry("feodo", "ip", C2_SERVER, "QakBot C2")])
        result = Pipeline(intel=c2_only).run(SimulatedReader(scenario.flows))
        classes = {a.threat_class for a in result.alerts}
        assert {ThreatClass.C2_BEACONING, ThreatClass.INTEL_MATCH} <= classes
        intel = [a for a in result.alerts if a.threat_class == ThreatClass.INTEL_MATCH]
        assert intel and all(a.destination_ip == C2_SERVER and a.severity == Severity.HIGH for a in intel)
        beacon = next(a for a in result.alerts if a.threat_class == ThreatClass.C2_BEACONING)
        assert beacon.evidence["intel_matches"][0]["source"] == "feodo"
        assert "intel_escalated_from" in beacon.evidence

    def test_without_intel_the_scenario_is_unchanged(self):
        scenario = build_scenario("beacon_30s", 1)
        result = Pipeline().run(SimulatedReader(scenario.flows))
        assert {a.threat_class for a in result.alerts} == {ThreatClass.C2_BEACONING}

    def test_imported_ja3_feeds_the_encrypted_blocklist(self):
        flows = [flow(i, dst="192.0.2.80").model_copy(update={"tls_version": "TLSv1.3", "ja3": BAD_JA3})
                 for i in range(3)]
        m = IntelMatcher([IntelEntry("sslbl", "ja3", BAD_JA3, "Tofsee")])
        result = Pipeline(intel=m).run(SimulatedReader(flows))
        (alert,) = [a for a in result.alerts if a.threat_class == ThreatClass.ENCRYPTED_SESSION_ANOMALY]
        assert alert.evidence["rules"] == ["blocklisted_fingerprint"]
        assert alert.evidence["blocklisted_ja3"] == {BAD_JA3: "sslbl: Tofsee"}
        assert alert.evidence["intel_matches"][0]["source"] == "sslbl"

    def test_intel_can_be_disabled_in_the_config(self, monkeypatch):
        from unishield.config import get_config, reset_config

        reset_config()
        monkeypatch.setattr(get_config().intel, "enabled", False)
        try:
            pipeline = Pipeline(intel=matcher())
            assert pipeline.intel.empty
        finally:
            reset_config()

    def test_anonymised_addresses_match_hashed_indicators(self, monkeypatch):
        from unishield.config import get_config, reset_config

        reset_config()
        cfg = get_config()
        monkeypatch.setattr(cfg.security, "anonymize_ips", True)
        monkeypatch.setattr(cfg.security, "ip_hash_salt", "pepper")
        try:
            m = IntelMatcher([IntelEntry("feodo", "ip", "198.51.100.42", "C2")], anonymize_salt="pepper")
            result = Pipeline(intel=m).run(SimulatedReader([flow(i) for i in range(3)]))
            (alert,) = [a for a in result.alerts if a.threat_class == ThreatClass.INTEL_MATCH]
            assert alert.destination_ip == hash_ip("198.51.100.42", "pepper")
        finally:
            reset_config()
