"""Unit tests for the DNS module: DGA per client and tunnelling per base domain."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from unishield.data.sample_generator import (
    SimulatedReader,
    build_scenario,
    generate_dga_traffic,
    generate_dns_tunnel_traffic,
)
from unishield.detectors.dns_detector import DNSDetector
from unishield.features.dns import DNSFeatureExtractor, bigram_rarity, looks_generated, split_domain
from unishield.ingest.pcap_reader import PcapReader
from unishield.processing.pipeline import Pipeline
from unishield.schemas.flow import NormalisedFlow, ProtocolType

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
DNS_CLASSES = {"DGA_DETECTED", "DNS_TUNNELLING"}


def query(t, name, rcode="NOERROR", qtype="A", src="10.0.1.5"):
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip=src, destination_ip="10.0.1.53",
                          source_port=40000, destination_port=53, protocol=ProtocolType.UDP,
                          dns_query=name, dns_record_type=qtype, dns_rcode=rcode)


def detect(flows):
    return DNSDetector().detect(flows, DNSFeatureExtractor().extract(flows), T0, T0 + timedelta(seconds=10))


@pytest.mark.parametrize("name,expected", [
    ("www.example.com", ("www", "example", "example.com")),
    ("mail.yahoo.co.uk", ("mail", "yahoo", "yahoo.co.uk")),
    ("a.b.c.tunnel.example", ("a.b.c", "tunnel", "tunnel.example")),
    ("localhost", ("", "localhost", "localhost")),
])
def test_split_domain(name, expected):
    assert split_domain(name) == expected


@pytest.mark.parametrize("label", ["google", "microsoft", "wikipedia", "cloudflare", "netflix", "linkedin",
                                   "stackoverflow", "speedtest", "telegram", "instagram"])
def test_common_names_do_not_look_generated(label):
    assert not looks_generated(label)
    assert bigram_rarity(label) < 0.3


@pytest.mark.parametrize("label", ["xq7kz2vjw9p", "qzxwvkjhtrp", "kq9x2zvbn7mw"])
def test_random_names_look_generated(label):
    assert looks_generated(label)


def test_short_labels_are_never_generated():
    assert not looks_generated("xqzk")


def test_dga_client_with_nxdomain_answers():
    flows = generate_dga_traffic(60, T0, seed=1)
    (alert,) = [a for a in detect(flows) if a.threat_class.value == "DGA_DETECTED"]
    assert alert.source_ip == "10.0.1.66" and alert.evidence["nxdomain_ratio"] >= 0.8
    assert alert.mitre_techniques == ["T1568.002"]


def test_dga_without_response_codes_uses_generated_share():
    flows = [f.model_copy(update={"dns_rcode": None}) for f in generate_dga_traffic(60, T0, seed=2)]
    assert [a.threat_class.value for a in detect(flows)] == ["DGA_DETECTED"]


def test_generated_names_that_resolve_are_not_dga():
    flows = generate_dga_traffic(60, T0, nxdomain_fraction=0.0, seed=3)
    assert detect(flows) == []


def test_dns_tunnel_is_reported_per_base_domain():
    flows = generate_dns_tunnel_traffic(80, T0, seed=1)
    (alert,) = detect(flows)
    assert alert.threat_class.value == "DNS_TUNNELLING"
    assert alert.evidence["base_domain"] == "exfil-tunnel.example"
    assert alert.source_ip == "10.0.1.77" and alert.severity.value == "HIGH"


def test_many_short_unique_subdomains_are_not_a_tunnel():
    """Regression: 60 lookups of img0..img59.example.com used to raise DGA_DETECTED."""
    flows = [query(0.08 * i, f"img{i}.example.com") for i in range(60)]
    assert detect(flows) == []


def test_nxdomain_ratio_uses_response_codes():
    flows = [query(i, f"host{i}.example.com", rcode="NXDOMAIN" if i < 3 else "NOERROR") for i in range(10)]
    assert DNSFeatureExtractor().extract(flows)["nxdomain_ratio"] == 0.3


def test_sample_pcap_keeps_nxdomain(sample_capture):
    flows = list(PcapReader(sample_capture.path).read())
    assert DNSFeatureExtractor().extract(flows)["nxdomain_ratio"] > 0


@pytest.mark.parametrize("name,expected", [("dga", {"DGA_DETECTED"}), ("dns_tunnel", {"DNS_TUNNELLING"}),
                                           ("benign_hard", set())])
def test_scenarios_through_the_pipeline(name, expected):
    result = Pipeline().run(SimulatedReader(build_scenario(name, 1).flows))
    assert {a.threat_class.value for a in result.alerts} & DNS_CLASSES == expected
