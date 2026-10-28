"""
Passive-mode verification: the static scan finds real capabilities and UniShield has none outside the
analyst-side transport; the tripwire confines that transport to allow-listed destinations outside the
monitored network and refuses every network call from readers, pipeline and detectors.
"""

from __future__ import annotations

import socket

import pytest

from unishield.evaluation.passive import (
    OUTBOUND_MODULE,
    _PolicyBypass,
    _Tripwire,
    runtime_check_detailed,
    sample_intel,
    scan_with_allowances,
    static_scan,
)
from unishield.export import transport
from unishield.export.policy import DestinationPolicy, DestinationRefused

pytestmark = pytest.mark.security

BAD_MODULE = '''
import subprocess
import requests
from scapy.all import send, sniff
from scapy.layers.inet import IP
import socket

def probe(host):
    s = socket.socket()
    s.connect((host, 22))
    send(IP(dst=host))
    subprocess.Popen(["ping", host])
'''


def test_static_scan_detects_active_capabilities(tmp_path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "bad.py").write_text(BAD_MODULE, encoding="utf-8")
    findings, files = static_scan(pkg)
    names = {f.name for f in findings}
    assert files == 1
    assert {"subprocess", "requests", "scapy.all.send", "scapy.all.sniff", "s.connect", "send",
            "subprocess.Popen"} <= names


def test_unishield_source_has_no_active_capabilities():
    findings, files = static_scan()
    assert files > 50
    assert findings == [], findings


def test_only_the_outbound_transport_has_the_scoped_allowance():
    findings, allowances, _ = scan_with_allowances()
    assert findings == []
    assert allowances and {a.file for a in allowances} == {OUTBOUND_MODULE}
    assert {a.name for a in allowances if a.kind == "import"} == {"socket", "ssl", "smtplib", "http.client"}


TRANSPORT_LIKE = """
import socket
import subprocess
import urllib.request

def deliver(host):
    socket.create_connection((host, 514))
    subprocess.Popen(["ping", host])
    urllib.request.urlopen("http://" + host)
"""


def test_allowance_is_limited_to_that_file_and_those_names(tmp_path):
    pkg = tmp_path / "unishield"
    (pkg / "export").mkdir(parents=True)
    (pkg / "export" / "transport.py").write_text(TRANSPORT_LIKE, encoding="utf-8")
    (pkg / "export" / "syslog.py").write_text(TRANSPORT_LIKE, encoding="utf-8")
    findings, allowances, _ = scan_with_allowances(pkg)
    in_transport = {f.name for f in findings if f.file == OUTBOUND_MODULE}
    assert in_transport == {"subprocess", "urllib.request", "subprocess.Popen", "urllib.request.urlopen"}
    assert {a.name for a in allowances} == {"socket", "socket.create_connection"}
    in_syslog = {f.name for f in findings if f.file == "unishield/export/syslog.py"}
    assert "socket.create_connection" in in_syslog                   # the same call elsewhere is a finding


def test_tripwire_blocks_remote_but_allows_loopback():
    with _Tripwire() as wire:
        with pytest.raises(PermissionError):
            socket.create_connection(("203.0.113.10", 80), timeout=0.1)
        with pytest.raises(PermissionError):
            socket.getaddrinfo("example.org", 443)
        import scapy.sendrecv as sendrecv

        with pytest.raises(PermissionError):
            sendrecv.send(None)
        a, b = socket.socketpair()                      # loopback pair, as asyncio uses internally
        a.sendall(b"x")
        assert b.recv(1) == b"x"
        a.close()
        b.close()
    assert len(wire.attempts) == 3
    assert socket.create_connection.__module__ == "socket"     # restored


HOME = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]


def test_transport_reaches_allow_listed_destinations_only():
    """A monitored-network destination is refused even when the policy check is bypassed."""
    policy = DestinationPolicy(["127.0.0.1"], HOME)
    with _Tripwire(outbound_policy=policy) as wire:
        with pytest.raises(DestinationRefused, match="monitored network"):
            transport.deliver_datagrams(policy, "10.1.2.3", 514, [b"x"])       # policy refuses first
        with pytest.raises(PermissionError):
            transport.deliver_datagrams(_PolicyBypass(), "10.1.2.3", 514, [b"x"])   # tripwire refuses
        with pytest.raises(PermissionError):
            transport.deliver_datagrams(_PolicyBypass(), "203.0.113.5", 514, [b"x"])  # not allow-listed
        assert transport.deliver_datagrams(policy, "127.0.0.1", 9, [b"x"]) == 1    # allow-listed (discard port)
    assert len(wire.attempts) == 2 and all("not allowed by the destination policy" in a for a in wire.attempts)
    assert "10.1.2.3" in wire.attempts[0] and len(wire.outbound) == 1


def test_transport_is_refused_without_a_policy_and_other_code_cannot_use_the_allowance():
    policy = DestinationPolicy(["192.0.2.0/24"], HOME)
    with _Tripwire() as wire:                                   # no outbound policy given
        with pytest.raises(PermissionError):
            transport.deliver_datagrams(_PolicyBypass(), "192.0.2.10", 514, [b"x"])
    with _Tripwire(outbound_policy=policy) as wire2:            # policy permits 192.0.2.10 ...
        with pytest.raises(PermissionError):
            socket.create_connection(("192.0.2.10", 514), timeout=0.1)   # ... but only for the transport
    assert len(wire.attempts) == 1 and len(wire2.attempts) == 1 and not wire2.outbound


def test_pipeline_readers_and_detectors_make_no_socket_calls(sample_capture, sample_zeek_dir, sample_flow_csv):
    """With every socket operation refused (loopback too), detection with intel loaded still completes."""
    from unishield.data.sample_generator import SimulatedReader, build_scenario
    from unishield.ingest.detect import open_reader
    from unishield.processing.pipeline import Pipeline

    intel = sample_intel()
    with _Tripwire(allow_loopback=False) as wire:
        for path in (sample_capture.path, sample_zeek_dir, sample_flow_csv):
            reader, _ = open_reader(path)
            Pipeline(intel=intel).run(reader)
        result = Pipeline(intel=intel).run(SimulatedReader(build_scenario("beacon_30s", 1).flows))
    assert wire.attempts == [] and wire.loopback_calls == 0 and wire.outbound == []
    assert any(a.threat_class.value == "INTEL_MATCH" for a in result.alerts)


def test_runtime_check_records_no_unexpected_network_attempts():
    attempts, exercised, outbound, refusals = runtime_check_detailed()
    assert attempts == []
    assert any(e.startswith("pipeline:pcap") for e in exercised)
    assert "api:/auth/login:200" in exercised
    assert any(e.startswith("api:/replay/demo:completed") for e in exercised)
    assert any(e.startswith("outbound:syslog/udp") for e in exercised)
    assert any(e.startswith("outbound:email") for e in exercised)
    assert outbound and all("127.0.0.1" in o for o in outbound)
    assert len(refusals) == 3 and all("10.0.0.5" in r for r in refusals)
