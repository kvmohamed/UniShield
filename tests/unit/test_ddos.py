"""Unit tests for DDoS features and detection (audit D2, D10)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.sample_generator import (
    SimulatedReader,
    generate_ddos_traffic,
    generate_normal_traffic,
)
from unishield.detectors.ddos_detector import DDoSDetector
from unishield.features.base import WindowContext, peak_per_second
from unishield.features.volume import VolumeFeatureExtractor, is_half_open
from unishield.processing.pipeline import Pipeline
from unishield.schemas.alert import Severity
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
WINDOW = WindowContext(start=T0, end=T0 + timedelta(seconds=10), observed_seconds=10.0)
DDOS_CLASSES = {"DDOS_VOLUMETRIC", "SYN_FLOOD", "UDP_FLOOD"}


def flow(t, src="198.18.0.1", dst="10.0.1.100", proto=ProtocolType.TCP, packets=1, size=60,
         duration=0.0, conn_state=None, flags=None, **kw):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip=dst,
                          source_port=40000, destination_port=80, protocol=proto, packet_count=packets,
                          byte_count=packets * size, duration=duration, conn_state=conn_state,
                          tcp_flags=flags, **kw)


def ddos_classes(result):
    return {a.threat_class.value for a in result.alerts} & DDOS_CLASSES


# ------------------------------------------------------------------ features

class TestPeakRate:
    def test_long_flow_is_spread_over_its_duration(self):
        download = flow(0, packets=18_000, size=1000, duration=30.0)
        assert peak_per_second([download], WINDOW, lambda f: f.packet_count) == pytest.approx(600)

    def test_zero_duration_flows_count_in_their_second(self):
        flows = [flow(0.1 * i) for i in range(10)] + [flow(5.5)]
        assert peak_per_second(flows, WINDOW, lambda f: 1) == 10

    def test_flows_outside_the_window_do_not_count(self):
        assert peak_per_second([flow(-3), flow(12)], WINDOW, lambda f: 1) == 0


class TestVolumeFeatures:
    def test_rates_use_the_observed_window_duration(self):
        f = VolumeFeatureExtractor().extract([flow(0, packets=20, duration=1.2)], WINDOW)
        assert f["packets_per_second"] == 2.0
        assert f["window_duration_sec"] == 10.0

    @pytest.mark.parametrize("conn_state,flags,expected", [
        ("S0", "SYN", True), ("REJ", "SYN", True), ("SF", "ACK,FIN,SYN", False),
        ("RST", "RST,SYN", False), (None, "SYN", True), (None, "ACK,SYN", False),
    ])
    def test_half_open_definition(self, conn_state, flags, expected):
        assert is_half_open(flow(0, conn_state=conn_state, flags=flags)) is expected

    def test_floods_against_different_targets_are_profiled_separately(self):
        syn = [flow(0.001 * i, src=f"198.18.0.{i % 250 + 1}", dst="10.0.0.5", conn_state="S0", flags="SYN")
               for i in range(2000)]
        udp = [flow(0.01 * i, src=f"198.19.0.{i % 250 + 1}", dst="10.0.0.9", proto=ProtocolType.UDP,
                    packets=120, size=800, duration=1.0, conn_state="S0") for i in range(300)]
        f = VolumeFeatureExtractor().extract(syn + udp, WINDOW)
        assert (f["syn_target_ip"], f["udp_target_ip"], f["vol_target_ip"]) == ("10.0.0.5", "10.0.0.9", "10.0.0.9")
        assert f["syn_target_rate_peak"] == 1000 and f["syn_target_syn_only_ratio"] == 1.0
        assert f["udp_target_udp_ratio"] == 1.0

    def test_empty_window(self):
        f = VolumeFeatureExtractor().extract([], WINDOW)
        assert f["total_packets"] == 0 and f["vol_target_ip"] is None


# ------------------------------------------------------------------ detector rules

class TestDDoSRules:
    def _features(self, **overrides):
        base = {"window_duration_sec": 10.0, "vol_target_ip": None, "syn_target_ip": None,
                "udp_target_ip": None}
        base.update(overrides)
        return base

    def test_syn_flood_needs_rate_and_half_open_share(self):
        det = DDoSDetector(thresholds={"syn_rate_threshold": 1000, "syn_only_ratio": 0.8})
        above = self._features(syn_target_ip="10.0.0.5", syn_target_rate_peak=1500, syn_target_syn_only_ratio=0.9,
                               syn_target_unique_sources=300)
        alerts = det.detect([flow(0)], above, T0, T0)
        assert [(a.threat_class.value, a.destination_ip) for a in alerts] == [("SYN_FLOOD", "10.0.0.5")]
        assert alerts[0].evidence["distributed"] is True
        below_rate = dict(above, syn_target_rate_peak=900)
        mostly_answered = dict(above, syn_target_syn_only_ratio=0.3)
        assert det.detect([flow(0)], below_rate, T0, T0) == []
        assert det.detect([flow(0)], mostly_answered, T0, T0) == []

    def test_volumetric_by_packets_or_bytes(self):
        det = DDoSDetector(thresholds={"packets_per_second": 10000, "bytes_per_second": 50_000_000})
        by_pps = self._features(vol_target_ip="10.0.0.9", vol_target_pps_peak=12000, vol_target_bps_peak=1e6)
        by_bps = self._features(vol_target_ip="10.0.0.9", vol_target_pps_peak=100, vol_target_bps_peak=6e7)
        quiet = self._features(vol_target_ip="10.0.0.9", vol_target_pps_peak=900, vol_target_bps_peak=1e6)
        assert [a.threat_class.value for a in det.detect([flow(0)], by_pps, T0, T0)] == ["DDOS_VOLUMETRIC"]
        assert [a.threat_class.value for a in det.detect([flow(0)], by_bps, T0, T0)] == ["DDOS_VOLUMETRIC"]
        assert det.detect([flow(0)], quiet, T0, T0) == []

    def test_udp_flood_needs_udp_share(self):
        det = DDoSDetector(thresholds={"udp_flood_pps": 8000, "udp_ratio": 0.7, "packets_per_second": 1e9})
        udp = self._features(udp_target_ip="10.0.0.9", udp_target_pps_peak=9000, udp_target_udp_ratio=0.95)
        mixed = dict(udp, udp_target_udp_ratio=0.5)
        assert [a.threat_class.value for a in det.detect([flow(0)], udp, T0, T0)] == ["UDP_FLOOD"]
        assert det.detect([flow(0)], mixed, T0, T0) == []

    def test_severity_is_at_least_medium_and_follows_levels(self):
        det = DDoSDetector(thresholds={"packets_per_second": 10000, "severity_levels": {
            "critical": {"packets_per_second": 50000}, "high": {"packets_per_second": 20000}}})
        sev = lambda pps: det.detect([flow(0)], self._features(vol_target_ip="x", vol_target_pps_peak=pps,
                                                               vol_target_bps_peak=0), T0, T0)[0].severity
        assert (sev(11000), sev(25000), sev(60000)) == (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


# ------------------------------------------------------------------ pipeline behaviour

def test_single_flow_after_quiet_period_is_not_a_flood():
    """Audit D2: one 20-packet flow after 30 s of silence used to read as 20,000 pps."""
    flows = generate_normal_traffic(40, T0, seed=1)
    gap_end = flows[-1].timestamp + timedelta(seconds=30)
    flows.append(NormalisedFlow(timestamp=gap_end, source_ip="10.0.1.7", destination_ip="10.0.1.8",
                                source_port=50000, destination_port=443, protocol=ProtocolType.TCP,
                                packet_count=20, byte_count=4000, duration=1.2, tcp_flags="SYN,ACK"))
    flows += generate_normal_traffic(20, gap_end + timedelta(seconds=1), seed=2)
    assert ddos_classes(Pipeline(enable_correlation=False).run(SimulatedReader(flows))) == set()


def test_short_flood_at_end_of_input_is_detected():
    """Audit D1: a flood in the last seconds of a file must still be analysed."""
    flows = generate_normal_traffic(30, T0, seed=3)
    flows += generate_ddos_traffic(6000, flows[-1].timestamp, syn_fraction=1.0, seed=3)
    assert "SYN_FLOOD" in ddos_classes(Pipeline(enable_correlation=False).run(SimulatedReader(flows)))


def test_flash_crowd_of_completed_connections_is_not_a_flood():
    crowd = [NormalisedFlow(timestamp=T0 + timedelta(milliseconds=20 * i), source_ip=f"198.51.100.{i % 250 + 1}",
                            destination_ip="10.0.2.10", source_port=50000 + i, destination_port=443,
                            protocol=ProtocolType.TCP, packet_count=40, byte_count=30000, orig_packets=15,
                            resp_packets=25, orig_bytes=1500, resp_bytes=28500, duration=2.0,
                            tcp_flags="ACK,FIN,PSH,SYN", conn_state="SF", direction=FlowDirection.INBOUND)
             for i in range(500)]
    assert ddos_classes(Pipeline(enable_correlation=False).run(SimulatedReader(crowd))) == set()


def test_short_flood_is_not_hidden_by_a_busier_destination():
    """A destination with more packets in long, steady transfers must not hide a short flood on another host."""
    from datetime import datetime, timedelta, timezone

    from unishield.features.base import WindowContext
    from unishield.features.volume import VolumeFeatureExtractor
    from unishield.schemas.flow import NormalisedFlow, ProtocolType

    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    flows = [NormalisedFlow(timestamp=t0, source_ip="10.0.0.2", destination_ip="10.0.0.80", protocol=ProtocolType.TCP,
                            packet_count=200_000, byte_count=200_000_000, duration=60.0)]          # long, steady
    flows += [NormalisedFlow(timestamp=t0 + timedelta(seconds=3), source_ip=f"10.0.1.{i}", destination_ip="198.51.100.9",
                             protocol=ProtocolType.ICMP, packet_count=300, byte_count=30_000, duration=0.0)
              for i in range(50)]                                                                   # 15,000 pkts in 1 s
    features = VolumeFeatureExtractor().extract(flows, WindowContext(t0, t0 + timedelta(seconds=10), 10.0))
    assert features["vol_target_ip"] == "198.51.100.9"
    assert features["vol_target_pps_peak"] >= 15_000
