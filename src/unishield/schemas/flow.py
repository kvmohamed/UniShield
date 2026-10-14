"""
UniShield — Normalised Flow Schema

Every input record (PCAP packet, Zeek log entry, flow CSV row) is
normalised into this schema before any processing. Fields that are
unavailable in a particular input source MUST be None — never fabricated.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from unishield.schemas.timeutil import ensure_utc


class ProtocolType(str, Enum):
    """Supported IP protocol identifiers."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class FlowDirection(str, Enum):
    """Traffic direction relative to the monitored network."""
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class InputSource(str, Enum):
    """Origin of the flow record."""
    PCAP = "pcap"
    PCAP_REPLAY = "pcap_replay"
    ZEEK_JSON = "zeek_json"
    FLOW_CSV = "flow_csv"
    FLOW_JSON = "flow_json"
    SIMULATED = "simulated"


class NormalisedFlow(BaseModel):
    """
    Standard flow record that all inputs are normalised into.

    Design principles:
    - Fields unavailable in a source are None (never fabricated).
    - IP anonymisation is applied downstream if configured.
    - No payload content is stored — metadata only.
    """

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this flow record",
    )
    timestamp: datetime = Field(
        ...,
        description="Timestamp of the first packet / record",
    )
    source_ip: str = Field(
        ...,
        description="Source IP address (may be hashed if anonymisation is on)",
    )
    destination_ip: str = Field(
        ...,
        description="Destination IP address",
    )
    source_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Source port (None for ICMP)",
    )
    destination_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination port (None for ICMP)",
    )
    protocol: ProtocolType = Field(
        default=ProtocolType.OTHER,
        description="IP protocol",
    )
    packet_count: int = Field(
        default=1,
        ge=0,
        description="Number of packets in this flow record",
    )
    byte_count: int = Field(
        default=0,
        ge=0,
        description="Total bytes in this flow record",
    )
    duration: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Flow duration in seconds",
    )

    # --- TCP metadata ---
    tcp_flags: Optional[str] = Field(
        default=None,
        description="TCP flags as string, e.g. 'SYN', 'SYN,ACK', 'FIN'",
    )

    # --- Direction ---
    direction: FlowDirection = Field(
        default=FlowDirection.UNKNOWN,
        description="Traffic direction relative to monitored network",
    )

    # --- DNS metadata (no payload decryption) ---
    dns_query: Optional[str] = Field(
        default=None,
        description="DNS query name if this is a DNS record",
    )
    dns_query_length: Optional[int] = Field(
        default=None,
        ge=0,
        description="Length of the DNS query name",
    )
    dns_record_type: Optional[str] = Field(
        default=None,
        description="DNS record type (A, AAAA, MX, TXT, etc.)",
    )

    # --- TLS metadata (no decryption — metadata only) ---
    tls_version: Optional[str] = Field(
        default=None,
        description="Advertised TLS version from ClientHello/ServerHello",
    )
    tls_cipher: Optional[str] = Field(
        default=None,
        description="Negotiated cipher suite",
    )
    ja3: Optional[str] = Field(
        default=None,
        description="JA3 fingerprint hash",
    )
    ja4: Optional[str] = Field(
        default=None,
        description="JA4 fingerprint hash",
    )

    # --- Provenance ---
    source: InputSource = Field(
        default=InputSource.PCAP,
        description="Origin of this record",
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v: Any) -> datetime:
        """Accept ISO strings, epoch floats or datetimes; always return aware UTC."""
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc)
        if isinstance(v, str):
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if isinstance(v, datetime):
            return ensure_utc(v)
        return v

    def to_anonymised(self, salt: str) -> "NormalisedFlow":
        """Return a copy with hashed IPs. Original object is not mutated."""

        def _hash_ip(ip: str) -> str:
            return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:16]

        data = self.model_dump()
        data["source_ip"] = _hash_ip(self.source_ip)
        data["destination_ip"] = _hash_ip(self.destination_ip)
        return NormalisedFlow(**data)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "timestamp": "2026-09-30T10:30:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "source_port": 54321,
                "destination_port": 443,
                "protocol": "TCP",
                "packet_count": 12,
                "byte_count": 1480,
                "duration": 0.5,
                "tcp_flags": "SYN",
                "direction": "outbound",
                "dns_query": None,
                "dns_query_length": None,
                "dns_record_type": None,
                "tls_version": "TLSv1.3",
                "tls_cipher": None,
                "ja3": None,
                "ja4": None,
                "source": "pcap",
            }
        }
    )
