"""
UniShield — Unit Tests for Flow Schema

Tests normalised flow record validation, field constraints,
timestamp parsing, and IP anonymisation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)


class TestNormalisedFlowCreation:
    """Test valid flow record construction."""

    def test_minimal_flow(self):
        """A flow with only required fields should be valid."""
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30, 10, 0, 0),
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
        )
        assert flow.source_ip == "192.168.1.1"
        assert flow.destination_ip == "10.0.0.1"
        assert flow.protocol == ProtocolType.OTHER
        assert flow.direction == FlowDirection.UNKNOWN
        assert flow.source == InputSource.PCAP
        assert flow.packet_count == 1
        assert flow.byte_count == 0
        assert flow.event_id is not None

    def test_full_flow(self):
        """A flow with all fields populated should be valid."""
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30, 10, 0, 0),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=443,
            protocol=ProtocolType.TCP,
            packet_count=12,
            byte_count=1480,
            duration=0.5,
            tcp_flags="SYN",
            direction=FlowDirection.OUTBOUND,
            dns_query=None,
            dns_query_length=None,
            dns_record_type=None,
            tls_version="TLSv1.3",
            tls_cipher=None,
            ja3=None,
            ja4=None,
            source=InputSource.PCAP,
        )
        assert flow.protocol == ProtocolType.TCP
        assert flow.source_port == 54321
        assert flow.destination_port == 443
        assert flow.byte_count == 1480
        assert flow.tls_version == "TLSv1.3"

    def test_dns_flow(self):
        """A DNS flow should carry query metadata."""
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30, 10, 0, 0),
            source_ip="192.168.1.1",
            destination_ip="8.8.8.8",
            source_port=12345,
            destination_port=53,
            protocol=ProtocolType.UDP,
            dns_query="example.com",
            dns_query_length=11,
            dns_record_type="A",
        )
        assert flow.dns_query == "example.com"
        assert flow.dns_query_length == 11
        assert flow.dns_record_type == "A"

    def test_null_optional_fields(self):
        """Optional fields must default to None, not fabricated values."""
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30, 10, 0, 0),
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
        )
        assert flow.source_port is None
        assert flow.destination_port is None
        assert flow.duration is None
        assert flow.tcp_flags is None
        assert flow.dns_query is None
        assert flow.tls_version is None
        assert flow.ja3 is None
        assert flow.ja4 is None


class TestFlowTimestampParsing:
    """Test flexible timestamp input handling."""

    def test_iso_string(self):
        flow = NormalisedFlow(
            timestamp="2026-09-30T10:00:00Z",
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
        )
        assert flow.timestamp.year == 2026
        assert flow.timestamp.month == 9

    def test_epoch_float(self):
        flow = NormalisedFlow(
            timestamp=1790841600.0,  # approx epoch
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
        )
        assert isinstance(flow.timestamp, datetime)
        assert flow.timestamp.tzinfo == timezone.utc

    def test_epoch_value_is_utc(self):
        flow = NormalisedFlow(timestamp=0, source_ip="1.1.1.1", destination_ip="2.2.2.2")
        assert flow.timestamp == datetime(1970, 1, 1, tzinfo=timezone.utc)

    def test_iso_string_is_aware_utc(self):
        flow = NormalisedFlow(
            timestamp="2026-09-30T10:00:00Z", source_ip="1.1.1.1", destination_ip="2.2.2.2"
        )
        assert flow.timestamp.tzinfo == timezone.utc

    def test_iso_string_with_offset_converted_to_utc(self):
        flow = NormalisedFlow(
            timestamp="2026-09-30T15:30:00+05:30", source_ip="1.1.1.1", destination_ip="2.2.2.2"
        )
        assert flow.timestamp == datetime(2026, 9, 30, 10, 0, tzinfo=timezone.utc)

    def test_datetime_object(self):
        """A naive datetime is interpreted as UTC and stored timezone-aware."""
        dt = datetime(2026, 9, 30, 10, 30, 0)
        flow = NormalisedFlow(
            timestamp=dt,
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
        )
        assert flow.timestamp == dt.replace(tzinfo=timezone.utc)

    def test_naive_and_aware_inputs_are_comparable(self):
        """Mixed inputs must not raise TypeError when windows compare them."""
        a = NormalisedFlow(timestamp=datetime(2026, 1, 1), source_ip="1.1.1.1",
                           destination_ip="2.2.2.2")
        b = NormalisedFlow(timestamp=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc),
                           source_ip="1.1.1.1", destination_ip="2.2.2.2")
        assert a.timestamp < b.timestamp


class TestFlowValidation:
    """Test field constraint validation."""

    def test_port_range_valid(self):
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30),
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=0,
            destination_port=65535,
        )
        assert flow.source_port == 0
        assert flow.destination_port == 65535

    def test_port_too_high(self):
        with pytest.raises(Exception):
            NormalisedFlow(
                timestamp=datetime(2026, 9, 30),
                source_ip="1.1.1.1",
                destination_ip="2.2.2.2",
                source_port=70000,
            )

    def test_negative_port(self):
        with pytest.raises(Exception):
            NormalisedFlow(
                timestamp=datetime(2026, 9, 30),
                source_ip="1.1.1.1",
                destination_ip="2.2.2.2",
                source_port=-1,
            )

    def test_negative_byte_count(self):
        with pytest.raises(Exception):
            NormalisedFlow(
                timestamp=datetime(2026, 9, 30),
                source_ip="1.1.1.1",
                destination_ip="2.2.2.2",
                byte_count=-100,
            )

    def test_negative_packet_count(self):
        with pytest.raises(Exception):
            NormalisedFlow(
                timestamp=datetime(2026, 9, 30),
                source_ip="1.1.1.1",
                destination_ip="2.2.2.2",
                packet_count=-1,
            )

    def test_negative_duration(self):
        with pytest.raises(Exception):
            NormalisedFlow(
                timestamp=datetime(2026, 9, 30),
                source_ip="1.1.1.1",
                destination_ip="2.2.2.2",
                duration=-0.5,
            )


class TestFlowAnonymisation:
    """Test IP hashing for anonymisation."""

    def test_anonymise_ips(self):
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30),
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
        )
        anon = flow.to_anonymised("test-salt")

        # Hashed IPs should differ from originals
        assert anon.source_ip != "192.168.1.1"
        assert anon.destination_ip != "10.0.0.1"

        # Same salt should produce same hash
        anon2 = flow.to_anonymised("test-salt")
        assert anon.source_ip == anon2.source_ip
        assert anon.destination_ip == anon2.destination_ip

    def test_different_salt_different_hash(self):
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30),
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
        )
        anon1 = flow.to_anonymised("salt-a")
        anon2 = flow.to_anonymised("salt-b")
        assert anon1.source_ip != anon2.source_ip

    def test_original_not_mutated(self):
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30),
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
        )
        _ = flow.to_anonymised("salt")
        assert flow.source_ip == "192.168.1.1"


class TestFlowSerialisation:
    """Test JSON serialisation round-trip."""

    def test_json_round_trip(self):
        flow = NormalisedFlow(
            timestamp=datetime(2026, 9, 30, 10, 0, 0),
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            protocol=ProtocolType.TCP,
            source_port=443,
            byte_count=1024,
        )
        json_str = flow.model_dump_json()
        restored = NormalisedFlow.model_validate_json(json_str)
        assert restored.source_ip == flow.source_ip
        assert restored.byte_count == flow.byte_count
        assert restored.protocol == flow.protocol

    def test_unique_event_ids(self):
        """Each flow should get a unique event_id by default."""
        flow1 = NormalisedFlow(
            timestamp=datetime(2026, 9, 30),
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
        )
        flow2 = NormalisedFlow(
            timestamp=datetime(2026, 9, 30),
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
        )
        assert flow1.event_id != flow2.event_id
