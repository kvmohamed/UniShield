"""
UniShield — Normalised Flow Schema

Every input record (PCAP packet, Zeek log entry, flow CSV row) is
normalised into this schema before any processing. Fields that are
unavailable in a particular input source MUST be None — never fabricated.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from unishield.schemas.timeutil import ensure_utc

# Anonymised addresses are the first 16 hex chars of a salted SHA-256.
# An IP literal can never match this (IPv4 has dots, IPv6 has colons).
_ANON_IP_RE = re.compile(r"^[0-9a-f]{16}$")


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
    ZEEK_TSV = "zeek_tsv"
    FLOW_CSV = "flow_csv"
    FLOW_JSON = "flow_json"
    FLOW_EXPORT = "flow_export"          # NetFlow v5/v9 or IPFIX received live
    SIMULATED = "simulated"


class NormalisedFlow(BaseModel):
    """
    Standard flow record that all inputs are normalised into.

    Design principles:
    - Fields unavailable in a source are None (never fabricated).
    - "orig" is the endpoint that initiated the connection (source_*),
      "resp" the endpoint that answered (destination_*).
    - IP anonymisation is applied by the normaliser if configured.
    - No payload content is stored — metadata only.
    """

    model_config = ConfigDict(
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "event_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "flow_id": "S-000001",
                "timestamp": "2026-09-30T10:30:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "93.184.216.34",
                "source_port": 54321,
                "destination_port": 443,
                "protocol": "TCP",
                "packet_count": 12,
                "byte_count": 1480,
                "orig_packets": 7,
                "resp_packets": 5,
                "orig_bytes": 620,
                "resp_bytes": 860,
                "duration": 0.5,
                "tcp_flags": "ACK,FIN,SYN",
                "conn_state": "SF",
                "direction": "outbound",
                "dns_query": None,
                "dns_query_length": None,
                "dns_record_type": None,
                "dns_rcode": None,
                "tls_version": "TLSv1.3",
                "tls_cipher": "TLS_AES_128_GCM_SHA256",
                "ja3": None,
                "ja4": None,
                "label": None,
                "source_type": "pcap",
            }
        },
    )

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this flow record",
    )
    flow_id: Optional[str] = Field(
        default=None,
        description="Connection/session identifier (e.g. Zeek uid). Records that are "
                    "segments of one long connection share it.",
    )
    timestamp: datetime = Field(
        ...,
        description="Timestamp of the first packet / record (UTC)",
    )
    source_ip: str = Field(
        ...,
        description="Originator IP address (16-hex hash if anonymisation is on)",
    )
    destination_ip: str = Field(
        ...,
        description="Responder IP address (16-hex hash if anonymisation is on)",
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
        description="Number of packets in this flow record (both directions)",
    )
    byte_count: int = Field(
        default=0,
        ge=0,
        description="Total bytes in this flow record (both directions)",
    )
    orig_packets: Optional[int] = Field(default=None, ge=0, description="Packets sent by the originator")
    resp_packets: Optional[int] = Field(default=None, ge=0, description="Packets sent by the responder")
    orig_bytes: Optional[int] = Field(default=None, ge=0, description="Bytes sent by the originator")
    resp_bytes: Optional[int] = Field(default=None, ge=0, description="Bytes sent by the responder")
    duration: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Flow duration in seconds",
    )

    # --- TCP metadata ---
    tcp_flags: Optional[str] = Field(
        default=None,
        description="TCP flags seen, comma-separated, e.g. 'SYN' or 'ACK,FIN,SYN'",
    )
    conn_state: Optional[str] = Field(
        default=None,
        description="Connection state (Zeek-style subset: S0, S1, SF, REJ, RST, OTH)",
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
        description="DNS query type (A, AAAA, MX, TXT, etc.)",
    )
    dns_rcode: Optional[str] = Field(
        default=None,
        description="DNS response code name (NOERROR, NXDOMAIN, SERVFAIL, ...)",
    )

    # --- TLS metadata (handshake fields only — no decryption) ---
    tls_version: Optional[str] = Field(
        default=None,
        description="Negotiated TLS version (ServerHello), else highest version offered "
                    "by the client, normalised as 'TLSv1.2' / 'TLSv1.3'",
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

    # --- Ground truth (labelled datasets only; never read by detectors) ---
    label: Optional[str] = Field(
        default=None,
        description="Dataset label for evaluation, e.g. 'BENIGN' or 'DDoS'",
    )

    # --- Provenance ---
    source_type: InputSource = Field(
        default=InputSource.PCAP,
        validation_alias=AliasChoices("source_type", "source"),
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

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Accept IPv4/IPv6 literals (returned in canonical form) or anonymised hashes."""
        value = v.strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            if _ANON_IP_RE.fullmatch(value):
                return value
        raise ValueError(f"not a valid IP address or anonymised hash: {v!r}")

    @property
    def end_time(self) -> datetime:
        """Timestamp of the last packet (start + duration)."""
        return self.timestamp + timedelta(seconds=self.duration or 0.0)

    def to_anonymised(self, salt: str) -> "NormalisedFlow":
        """Return a copy with hashed IPs. Original object is not mutated."""

        def _hash_ip(ip: str) -> str:
            return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:16]

        return self.model_copy(update={
            "source_ip": _hash_ip(self.source_ip),
            "destination_ip": _hash_ip(self.destination_ip),
        })
