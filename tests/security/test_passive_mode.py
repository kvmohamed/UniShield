"""Passive-mode verification: the static scan finds real capabilities, and UniShield has none."""

from __future__ import annotations

import socket

import pytest

from unishield.evaluation.passive import _Tripwire, runtime_check, static_scan

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


def test_runtime_check_records_no_network_attempts():
    attempts, exercised = runtime_check()
    assert attempts == []
    assert any(e.startswith("pipeline:pcap") for e in exercised)
    assert any(e.startswith("api:/replay/demo:completed") for e in exercised)
