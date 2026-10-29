"""Brute-force and spam rules: what must and must not raise an alert."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from unishield.detectors.service_abuse_detector import ServiceAbuseDetector
from unishield.features.base import WindowContext
from unishield.features.service_abuse import ServiceAbuseFeatureExtractor
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def conn(t, src="198.18.0.150", dst="10.0.2.22", dport=22, state="SF", nbytes=4000, duration=2.0,
         direction=FlowDirection.INBOUND, proto=ProtocolType.TCP):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=40000, destination_port=dport, protocol=proto, byte_count=nbytes,
                          packet_count=1 if state == "S0" else 12, duration=duration, conn_state=state,
                          direction=direction)


def run(flows, window_sec=10, extractor=None, detector=None):
    """Feed flows window by window (10 s, like the pipeline); return all alerts."""
    extractor = extractor or ServiceAbuseFeatureExtractor()
    detector = detector or ServiceAbuseDetector()
    alerts = []
    end = max(f.timestamp for f in flows)
    start = T0
    while start <= end:
        stop = start + timedelta(seconds=window_sec)
        batch = [f for f in flows if start <= f.timestamp < stop]
        if batch:
            features = extractor.extract(batch, WindowContext(start, stop, float(window_sec)))
            alerts += detector.detect(batch, features, start, stop)
        start = stop
    return alerts


# --- brute force ---------------------------------------------------------------

def test_password_guessing_is_detected():
    alerts = run([conn(i * 0.5) for i in range(80)])                 # 2 attempts/s on SSH
    (alert,) = [a for a in alerts if a.threat_class.value == "BRUTE_FORCE"]
    assert (alert.source_ip, alert.destination_ip) == ("198.18.0.150", "10.0.2.22")
    assert alert.evidence["destination_port"] == 22 and alert.evidence["attempts"] >= 30
    assert alert.mitre_techniques == ["T1110"]
    assert "login success is not visible" in alert.evidence["summary"]


def test_slow_attempts_accumulate_across_windows():
    alerts = run([conn(i * 1.5) for i in range(45)])                 # 40 per minute, < 7 per window
    assert any(a.threat_class.value == "BRUTE_FORCE" for a in alerts)


@pytest.mark.parametrize("flows", [
    [conn(i * 3.0) for i in range(30)],                                  # 20 per minute: below threshold
    [conn(i * 0.5, state="S0", nbytes=60, duration=0.0) for i in range(80)],   # SYN flood on 22: never connects
    [conn(i * 0.5, dport=443) for i in range(80)],                       # not a login port
    [conn(i * 0.5, nbytes=5_000_000, duration=60) for i in range(80)],   # long transfers, not login attempts
    [conn(i * 0.5, dst=f"10.0.2.{i % 250}") for i in range(80)],         # one attempt per host: a sweep
])
def test_non_brute_force_patterns_are_quiet(flows):
    assert not [a for a in run(flows) if a.threat_class.value == "BRUTE_FORCE"]


def test_brute_force_is_reported_once_per_realert_period():
    detector = ServiceAbuseDetector()
    alerts = run([conn(i * 0.25) for i in range(800)], detector=detector)    # 4 per second for 200 s
    brute = [a for a in alerts if a.threat_class.value == "BRUTE_FORCE"]
    assert len(brute) == 2                                                   # MEDIUM, then HIGH when it grows
    assert [a.severity.value for a in brute] == ["MEDIUM", "HIGH"]


# --- spam ------------------------------------------------------------------------

def smtp(t, dst, src="10.0.1.88", state="SF", direction=FlowDirection.OUTBOUND):
    return conn(t, src=src, dst=dst, dport=25, state=state, nbytes=60 if state == "S0" else 5000,
                duration=0.0 if state == "S0" else 1.0, direction=direction)


def test_direct_delivery_to_many_mail_servers_is_spam():
    flows = [smtp(i * 2.0, f"203.0.113.{i}", state="S0" if i % 2 else "SF") for i in range(40)]
    (alert,) = [a for a in run(flows) if a.threat_class.value == "SPAM_ACTIVITY"]
    assert alert.source_ip == "10.0.1.88" and alert.evidence["smtp_destinations"] >= 20
    assert alert.mitre_techniques == []
    assert "message content is not visible" in alert.evidence["summary"]


@pytest.mark.parametrize("flows", [
    [smtp(i * 2.0, "203.0.113.5") for i in range(100)],                                   # one relay
    [smtp(i * 2.0, f"203.0.113.{i}") for i in range(15)],                                 # few servers
    [smtp(i * 2.0, "10.0.1.25", src=f"203.0.113.{i}", direction=FlowDirection.INBOUND)
     for i in range(60)],                                                                  # inbound to our MX
    [smtp(i * 2.0, f"10.0.3.{i}", direction=FlowDirection.INTERNAL) for i in range(60)],  # internal relays
    [smtp(i * 20.0, f"203.0.113.{i}") for i in range(40)],                                # 40 servers over 13 min
])
def test_non_spam_patterns_are_quiet(flows):
    assert not [a for a in run(flows) if a.threat_class.value == "SPAM_ACTIVITY"]


def test_mail_server_role_downgrades_spam_to_info():
    from unishield.assets import AssetInventory
    from unishield.config import AssetInventoryConfig
    from unishield.data.sample_generator import SimulatedReader, generate_spam_traffic
    from unishield.processing.pipeline import Pipeline

    flows = generate_spam_traffic(120, T0, sender="10.0.1.25", seed=3)
    plain = Pipeline().run(SimulatedReader(flows)).alerts
    assert any(a.threat_class.value == "SPAM_ACTIVITY" and a.severity.value != "INFO" for a in plain)
    inventory = AssetInventory(AssetInventoryConfig.model_validate(
        {"assets": [{"name": "mx", "addresses": ["10.0.1.25"], "roles": ["mail_server"]}]}))
    tuned = Pipeline(assets=inventory).run(SimulatedReader(flows)).alerts
    spam = [a for a in tuned if a.threat_class.value == "SPAM_ACTIVITY"]
    assert spam and all(a.severity.value == "INFO" for a in spam)


# --- state -------------------------------------------------------------------------

def test_state_round_trip_keeps_history():
    import json

    first = ServiceAbuseFeatureExtractor()
    run([conn(i * 1.5) for i in range(20)], extractor=first)          # 20 attempts: not yet an alert
    restored = ServiceAbuseFeatureExtractor()
    restored.load_state_dict(json.loads(json.dumps(first.state_dict())))
    later = [conn(30 + i * 1.5) for i in range(15)]
    features = restored.extract(later, WindowContext(T0 + timedelta(seconds=30), T0 + timedelta(seconds=60), 30.0))
    (candidate,) = features["bruteforce_candidates"]
    assert candidate["attempts"] >= 30                                 # the restored attempts still count
