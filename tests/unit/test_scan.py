"""Unit tests for scan features and detection (audit D7)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.sample_generator import SimulatedReader
from unishield.detectors.scan_detector import ScanDetector
from unishield.features.base import WindowContext
from unishield.features.scan import ScanFeatureExtractor, is_attempt, is_failed
from unishield.processing.pipeline import Pipeline
from unishield.processing.sessionizer import Sessionizer
from unishield.schemas.flow import NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
WINDOW = WindowContext(start=T0, end=T0 + timedelta(seconds=10), observed_seconds=10.0)
SCAN_CLASSES = {"PORT_SCAN", "HOST_SCAN", "RECONNAISSANCE"}


def attempt(t, src, dst, dport, state="S0", sport=40000, packets=1, flags="SYN", **kw):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=sport, destination_port=dport, protocol=ProtocolType.TCP,
                          packet_count=packets, byte_count=60 * packets, duration=0.01,
                          conn_state=state, tcp_flags=flags, **kw)


def completed(t, src, dst, dport, sport=None):
    return attempt(t, src, dst, dport, state="SF", sport=sport or 50000 + int(t * 100), packets=20,
                   flags="ACK,FIN,PSH,SYN")


def detect(flows):
    features = ScanFeatureExtractor().extract(flows, WINDOW)
    return ScanDetector().detect(flows, features, WINDOW.start, WINDOW.end)


# ------------------------------------------------------------------ features

@pytest.mark.parametrize("sport,dport,expected", [
    (50000, 443, True), (443, 50000, False), (53, 40000, False), (None, None, True), (2000, 3000, True),
])
def test_replies_from_service_ports_are_not_attempts(sport, dport, expected):
    assert is_attempt(attempt(0, "10.0.0.1", "10.0.0.2", dport, sport=sport)) is expected


@pytest.mark.parametrize("state,packets,resp,flags,expected", [
    ("S0", 1, None, "SYN", True), ("REJ", 2, None, "SYN", True), ("RST", 3, None, "RST,SYN", True),
    ("RST", 12, None, "ACK,RST,SYN", False), ("SF", 20, None, "ACK,FIN,SYN", False),
    (None, 1, 0, None, True), (None, 4, 2, None, False), (None, 1, None, "SYN", True),
])
def test_failed_attempt_definition(state, packets, resp, flags, expected):
    f = attempt(0, "10.0.0.1", "10.0.0.2", 22, state=state, packets=packets, flags=flags, resp_packets=resp)
    assert is_failed(f) is expected


def test_port_and_host_scanners_are_profiled_separately():
    port_scan = [attempt(0.03 * i, "198.51.100.66", "10.0.0.20", i + 1, state="REJ") for i in range(60)]
    sweep = [attempt(0.03 * i, "198.51.100.77", f"10.0.2.{i + 1}", 22) for i in range(40)]
    f = ScanFeatureExtractor().extract(port_scan + sweep, WINDOW)
    assert (f["top_scanner_ip"], f["top_scanner_port_count"]) == ("198.51.100.66", 60)
    assert (f["top_host_scanner_ip"], f["top_host_scanner_horizontal"]) == ("198.51.100.77", 40)
    by_source = {c["source_ip"]: c for c in f["scan_candidates"]}
    assert by_source["198.51.100.66"]["vertical_ports"] == 60
    assert by_source["198.51.100.77"]["horizontal_port"] == 22
    assert by_source["198.51.100.77"]["failed_ratio"] == 1.0


def test_burst_is_per_source():
    flows = [completed(0.01 * i, f"10.0.1.{i + 1}", "93.184.216.34", 443) for i in range(50)]
    assert ScanFeatureExtractor().extract(flows, WINDOW)["burst_connections"] == 1


# ------------------------------------------------------------------ detection

def test_port_scan_attributed_to_the_scanner_and_target():
    flows = [attempt(0.03 * i, "198.51.100.66", "10.0.0.20", i + 1, state="REJ") for i in range(60)]
    flows += [completed(0.1 * i, "10.0.1.5", f"203.0.113.{i + 1}", 443) for i in range(30)]
    alerts = detect(flows)
    assert [(a.threat_class.value, a.source_ip, a.destination_ip) for a in alerts] == \
        [("PORT_SCAN", "198.51.100.66", "10.0.0.20")]
    assert alerts[0].evidence["max_ports_on_one_host"] == 60


def test_host_sweep_with_failures_is_host_scan():
    flows = [attempt(0.02 * i, "198.51.100.77", f"10.0.2.{i + 1}", 22) for i in range(30)]
    alerts = detect(flows)
    assert [(a.threat_class.value, a.source_ip) for a in alerts] == [("HOST_SCAN", "198.51.100.77")]
    assert alerts[0].evidence["swept_port"] == 22


def test_browsing_many_cdn_hosts_is_not_a_host_scan():
    """Completed connections to 25 hosts on 443 used to raise HOST_SCAN (>= 10 hosts)."""
    flows = [completed(0.12 * i, "192.168.1.25", f"203.0.113.{100 + i}", 443) for i in range(25)]
    assert detect(flows) == []


def test_very_wide_sweep_is_reported_even_if_hosts_answer():
    flows = [completed(0.05 * i, "198.51.100.88", f"10.0.3.{i + 1}", 22) for i in range(60)]
    assert [a.threat_class.value for a in detect(flows)] == ["HOST_SCAN"]


def test_many_ports_on_many_hosts_needs_failures():
    p2p = [completed(0.05 * i, "10.0.1.9", f"203.0.113.{i + 1}", 6000 + i) for i in range(40)]
    assert detect(p2p) == []
    probing = [attempt(0.05 * i, "198.51.100.99", f"10.0.4.{i % 20 + 1}", 7000 + i) for i in range(40)]
    assert [a.threat_class.value for a in detect(probing)] == ["PORT_SCAN"]


def test_failed_burst_below_scan_thresholds_is_reconnaissance():
    flows = [attempt(0.04 * i, "198.51.100.55", f"10.0.5.{i % 4 + 1}", [22, 23, 3389][i % 3]) for i in range(40)]
    alerts = detect(flows)
    assert [(a.threat_class.value, a.source_ip) for a in alerts] == [("RECONNAISSANCE", "198.51.100.55")]


def test_two_scanners_in_one_window_get_two_alerts():
    flows = [attempt(0.03 * i, "198.51.100.66", "10.0.0.20", i + 1) for i in range(40)]
    flows += [attempt(0.03 * i, "198.51.100.67", "10.0.0.21", i + 1) for i in range(40)]
    assert sorted(a.source_ip for a in detect(flows)) == ["198.51.100.66", "198.51.100.67"]


def test_bidirectional_https_packets_are_not_a_port_scan():
    """Audit D7: 40 normal HTTPS connections used to raise PORT_SCAN against the server."""
    packets = []
    t = T0
    for conn in range(40):
        cport = 50000 + conn
        for i, flags in enumerate(["SYN", "SYN,ACK", "ACK", "PSH,ACK", "PSH,ACK", "FIN,ACK", "FIN,ACK"]):
            t += timedelta(milliseconds=30)
            c2s = i not in (1, 4, 6)
            packets.append(NormalisedFlow(
                timestamp=t, source_ip="10.0.1.9" if c2s else "93.184.216.34",
                destination_ip="93.184.216.34" if c2s else "10.0.1.9",
                source_port=cport if c2s else 443, destination_port=443 if c2s else cport,
                protocol=ProtocolType.TCP, packet_count=1, byte_count=600, duration=0.0, tcp_flags=flags))
    flows = list(Sessionizer().process(packets))
    result = Pipeline(enable_correlation=False).run(SimulatedReader(flows))
    assert {a.threat_class.value for a in result.alerts} & SCAN_CLASSES == set()


def test_unidirectional_reply_records_are_ignored():
    """Flow exports with one record per direction: server→client records must not look like a scan."""
    replies = [attempt(0.05 * i, "93.184.216.34", "10.0.1.9", 50000 + i, sport=443, state=None,
                       flags="ACK,PSH", packets=10) for i in range(60)]
    assert detect(replies) == []
