"""Unit tests for the normalisation layer (direction, naming, anonymisation)."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import pytest

from unishield.processing.normalization import Normalizer, normalize_tls_version
from unishield.schemas.flow import FlowDirection, NormalisedFlow

HOME = ["10.0.0.0/8", "192.168.0.0/16", "fc00::/7"]


def _flow(src, dst, **kw):
    return NormalisedFlow(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                          source_ip=src, destination_ip=dst, **kw)


@pytest.mark.parametrize("src,dst,expected", [
    ("192.168.1.5", "93.184.216.34", FlowDirection.OUTBOUND),
    ("93.184.216.34", "10.1.2.3", FlowDirection.INBOUND),
    ("10.0.0.1", "192.168.1.1", FlowDirection.INTERNAL),
    ("8.8.8.8", "1.1.1.1", FlowDirection.UNKNOWN),
    ("fd00::1", "2001:db8::1", FlowDirection.OUTBOUND),
    ("2001:db8::1", "fd12:3456::9", FlowDirection.INBOUND),
])
def test_direction_inferred_from_home_networks(src, dst, expected):
    assert Normalizer(HOME).normalize(_flow(src, dst)).direction == expected


def test_source_supplied_direction_is_kept():
    flow = _flow("192.168.1.5", "93.184.216.34", direction=FlowDirection.INBOUND)
    assert Normalizer(HOME).normalize(flow).direction == FlowDirection.INBOUND


def test_no_home_networks_leaves_direction_unknown():
    assert Normalizer([]).normalize(_flow("192.168.1.5", "8.8.8.8")).direction == FlowDirection.UNKNOWN


def test_unchanged_flow_is_returned_as_is():
    flow = _flow("8.8.8.8", "1.1.1.1")
    assert Normalizer(HOME).normalize(flow) is flow


def test_anonymisation_runs_after_direction_inference():
    n = Normalizer(HOME, anonymize=True, salt="s3cret")
    a = n.normalize(_flow("192.168.1.5", "93.184.216.34"))
    b = n.normalize(_flow("192.168.1.5", "8.8.4.4"))
    assert a.direction == FlowDirection.OUTBOUND
    assert re.fullmatch(r"[0-9a-f]{16}", a.source_ip)
    assert a.source_ip == b.source_ip          # consistent per address
    assert a.destination_ip != b.destination_ip


def test_default_salt_with_anonymisation_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="unishield.processing.normalization"):
        Normalizer(HOME, anonymize=True, salt="change-this-salt")
    assert "default or empty salt" in caplog.text


def test_dns_query_length_filled():
    flow = _flow("10.0.0.1", "10.0.0.53", dns_query="www.example.com")
    assert Normalizer(HOME).normalize(flow).dns_query_length == 15


@pytest.mark.parametrize("raw,expected", [
    ("TLSv12", "TLSv1.2"),
    ("TLSv13", "TLSv1.3"),
    ("TLSv10", "TLSv1.0"),
    ("TLSv1", "TLSv1.0"),
    ("TLS 1.2", "TLSv1.2"),
    ("tlsv1.3", "TLSv1.3"),
    ("TLSv1.1", "TLSv1.1"),
    ("SSLv3", "SSLv3"),
    ("DTLSv12", "DTLSv12"),     # unknown spellings are kept
    ("", None),
    (None, None),
])
def test_tls_version_names_normalised(raw, expected):
    assert normalize_tls_version(raw) == expected


def test_tls_version_normalised_on_flow():
    flow = _flow("10.0.0.1", "93.184.216.34", tls_version="TLSv12")
    assert Normalizer(HOME).normalize(flow).tls_version == "TLSv1.2"


def test_from_config_uses_network_and_security_sections():
    from unishield.config import UnishieldConfig
    config = UnishieldConfig(network={"home_networks": ["172.16.0.0/12"]},
                             security={"anonymize_ips": False})
    n = Normalizer.from_config(config)
    assert n.normalize(_flow("172.16.5.5", "8.8.8.8")).direction == FlowDirection.OUTBOUND
