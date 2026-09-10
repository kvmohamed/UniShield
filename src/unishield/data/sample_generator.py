"""
UniShield — Sample Data Generator

Generates synthetic traffic data for testing and demonstration.
Creates realistic flow records with embedded attack patterns.

IMPORTANT: This generates SIMULATED data for testing only.
It does NOT generate real attacks or interact with any network.

Available scenarios:
    1. Normal baseline traffic
    2. DDoS / SYN flood
    3. Port scanning
    4. C2 beaconing
    5. Data exfiltration
    6. Mixed (all attack types)
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)


# ---------------------------------------------------------------------------
# IP ranges for simulation
# ---------------------------------------------------------------------------

INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "192.168.1."]
EXTERNAL_IPS = [
    "203.0.113.50", "198.51.100.100", "198.51.100.200",
    "203.0.113.75", "93.184.216.34", "172.217.14.206",
    "151.101.1.140", "104.16.132.229", "13.107.42.14",
]
ATTACKER_IPS = ["198.18.0.100", "198.18.0.101", "198.18.0.102"]
C2_SERVER = "198.51.100.42"
EXFIL_DEST = "203.0.113.99"


def _random_internal_ip() -> str:
    subnet = random.choice(INTERNAL_SUBNETS)
    return f"{subnet}{random.randint(1, 254)}"


def _random_external_ip() -> str:
    return random.choice(EXTERNAL_IPS)


# ---------------------------------------------------------------------------
# Normal traffic generator
# ---------------------------------------------------------------------------

def generate_normal_traffic(
    count: int = 500,
    start_time: datetime | None = None,
) -> list[NormalisedFlow]:
    """Generate normal baseline traffic flows."""
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    flows = []
    current_time = start_time

    for _ in range(count):
        # Random time increment (100ms - 2s)
        current_time += timedelta(milliseconds=random.randint(100, 2000))

        proto = random.choices(
            [ProtocolType.TCP, ProtocolType.UDP, ProtocolType.ICMP],
            weights=[0.7, 0.25, 0.05],
        )[0]

        # Common destination ports for normal traffic
        dst_port = random.choice([80, 443, 53, 22, 8080, 993, 587]) if proto != ProtocolType.ICMP else None
        src_port = random.randint(1024, 65535) if proto != ProtocolType.ICMP else None

        direction = random.choice([FlowDirection.OUTBOUND, FlowDirection.INBOUND])
        if direction == FlowDirection.OUTBOUND:
            src_ip = _random_internal_ip()
            dst_ip = _random_external_ip()
        else:
            src_ip = _random_external_ip()
            dst_ip = _random_internal_ip()

        flow = NormalisedFlow(
            timestamp=current_time,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            packet_count=random.randint(1, 50),
            byte_count=random.randint(64, 15000),
            duration=round(random.uniform(0.01, 30.0), 3),
            tcp_flags="SYN,ACK" if proto == ProtocolType.TCP else None,
            direction=direction,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    return flows


# ---------------------------------------------------------------------------
# DDoS / SYN Flood traffic
# ---------------------------------------------------------------------------

def generate_ddos_traffic(
    count: int = 2000,
    start_time: datetime | None = None,
    target_ip: str = "10.0.1.100",
) -> list[NormalisedFlow]:
    """Generate DDoS attack traffic (high rate, many sources)."""
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    flows = []
    current_time = start_time

    for _ in range(count):
        # Very fast arrivals (1-10ms apart)
        current_time += timedelta(milliseconds=random.randint(1, 10))

        # SYN flood pattern: mostly SYN-only, small packets
        is_syn_flood = random.random() < 0.8

        if is_syn_flood:
            flow = NormalisedFlow(
                timestamp=current_time,
                source_ip=f"198.18.{random.randint(0, 255)}.{random.randint(1, 254)}",
                destination_ip=target_ip,
                source_port=random.randint(1024, 65535),
                destination_port=random.choice([80, 443, 8080]),
                protocol=ProtocolType.TCP,
                packet_count=1,
                byte_count=random.randint(40, 60),
                duration=0.0,
                tcp_flags="SYN",
                direction=FlowDirection.INBOUND,
                source=InputSource.SIMULATED,
            )
        else:
            # UDP flood
            flow = NormalisedFlow(
                timestamp=current_time,
                source_ip=f"198.18.{random.randint(0, 255)}.{random.randint(1, 254)}",
                destination_ip=target_ip,
                source_port=random.randint(1024, 65535),
                destination_port=random.choice([53, 123, 1900]),
                protocol=ProtocolType.UDP,
                packet_count=random.randint(1, 5),
                byte_count=random.randint(64, 1500),
                duration=0.001,
                direction=FlowDirection.INBOUND,
                source=InputSource.SIMULATED,
            )

        flows.append(flow)

    return flows


# ---------------------------------------------------------------------------
# Port scan traffic
# ---------------------------------------------------------------------------

def generate_scan_traffic(
    count: int = 200,
    start_time: datetime | None = None,
    scanner_ip: str | None = None,
    target_ip: str | None = None,
) -> list[NormalisedFlow]:
    """Generate port scanning traffic."""
    if start_time is None:
        start_time = datetime.now(timezone.utc)
    if scanner_ip is None:
        scanner_ip = random.choice(ATTACKER_IPS)
    if target_ip is None:
        target_ip = _random_internal_ip()

    flows = []
    current_time = start_time
    scanned_ports = random.sample(range(1, 65536), min(count, 1000))

    for i in range(count):
        current_time += timedelta(milliseconds=random.randint(10, 200))

        port = scanned_ports[i % len(scanned_ports)]

        flow = NormalisedFlow(
            timestamp=current_time,
            source_ip=scanner_ip,
            destination_ip=target_ip if random.random() < 0.7 else _random_internal_ip(),
            source_port=random.randint(1024, 65535),
            destination_port=port,
            protocol=ProtocolType.TCP,
            packet_count=random.randint(1, 3),
            byte_count=random.randint(40, 120),
            duration=round(random.uniform(0.001, 0.5), 3),
            tcp_flags="SYN",
            direction=FlowDirection.INBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    return flows


# ---------------------------------------------------------------------------
# C2 Beaconing traffic
# ---------------------------------------------------------------------------

def generate_beacon_traffic(
    beacon_count: int = 50,
    start_time: datetime | None = None,
    interval_sec: float = 60.0,
    jitter_percent: float = 5.0,
    internal_ip: str | None = None,
) -> list[NormalisedFlow]:
    """Generate C2 beaconing traffic with periodic intervals."""
    if start_time is None:
        start_time = datetime.now(timezone.utc)
    if internal_ip is None:
        internal_ip = "10.0.1.50"

    flows = []
    current_time = start_time

    for _ in range(beacon_count):
        # Add jitter to interval
        jitter = interval_sec * jitter_percent / 100.0
        actual_interval = interval_sec + random.uniform(-jitter, jitter)
        current_time += timedelta(seconds=max(1.0, actual_interval))

        flow = NormalisedFlow(
            timestamp=current_time,
            source_ip=internal_ip,
            destination_ip=C2_SERVER,
            source_port=random.randint(49152, 65535),
            destination_port=443,
            protocol=ProtocolType.TCP,
            packet_count=random.randint(3, 8),
            byte_count=random.randint(200, 500),  # Consistent small payloads
            duration=round(random.uniform(0.1, 2.0), 3),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            tls_version="TLSv1.2",
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    return flows


# ---------------------------------------------------------------------------
# Data Exfiltration traffic
# ---------------------------------------------------------------------------

def generate_exfil_traffic(
    count: int = 100,
    start_time: datetime | None = None,
    internal_ip: str | None = None,
) -> list[NormalisedFlow]:
    """Generate data exfiltration traffic (high outbound volumes)."""
    if start_time is None:
        start_time = datetime.now(timezone.utc)
    if internal_ip is None:
        internal_ip = "10.0.2.200"

    flows = []
    current_time = start_time

    for _ in range(count):
        current_time += timedelta(seconds=random.uniform(1, 10))

        # Large outbound transfers
        flow = NormalisedFlow(
            timestamp=current_time,
            source_ip=internal_ip,
            destination_ip=EXFIL_DEST,
            source_port=random.randint(49152, 65535),
            destination_port=random.choice([443, 8443, 4444, 9090]),
            protocol=ProtocolType.TCP,
            packet_count=random.randint(50, 500),
            byte_count=random.randint(500_000, 5_000_000),  # 500KB - 5MB per flow
            duration=round(random.uniform(5.0, 120.0), 3),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    return flows


# ---------------------------------------------------------------------------
# Mixed scenario (baseline + attacks)
# ---------------------------------------------------------------------------

def generate_mixed_scenario(
    normal_count: int = 500,
    ddos_count: int = 300,
    scan_count: int = 100,
    beacon_count: int = 30,
    exfil_count: int = 50,
    start_time: datetime | None = None,
) -> list[NormalisedFlow]:
    """
    Generate a mixed traffic scenario with normal traffic and
    embedded attack patterns. All flows are merged and sorted
    by timestamp to simulate real traffic.
    """
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    all_flows = []

    # Normal background traffic
    all_flows.extend(generate_normal_traffic(normal_count, start_time))

    # DDoS starts 30 seconds in
    ddos_start = start_time + timedelta(seconds=30)
    all_flows.extend(generate_ddos_traffic(ddos_count, ddos_start))

    # Scan starts 60 seconds in
    scan_start = start_time + timedelta(seconds=60)
    all_flows.extend(generate_scan_traffic(scan_count, scan_start))

    # Beaconing throughout
    all_flows.extend(generate_beacon_traffic(beacon_count, start_time))

    # Exfiltration starts 120 seconds in
    exfil_start = start_time + timedelta(seconds=120)
    all_flows.extend(generate_exfil_traffic(exfil_count, exfil_start))

    # Sort all by timestamp
    all_flows.sort(key=lambda f: f.timestamp)

    return all_flows


# ---------------------------------------------------------------------------
# File writer for sample data
# ---------------------------------------------------------------------------

def save_sample_flows(
    flows: list[NormalisedFlow],
    output_path: Path | str,
    format: str = "json",
) -> Path:
    """
    Save sample flows to a file.

    Args:
        flows: List of NormalisedFlow records.
        output_path: Output file path.
        format: "json" for JSON lines, "csv" for CSV.

    Returns:
        Path to the saved file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if format == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            for flow in flows:
                line = flow.model_dump_json()
                f.write(line + "\n")
    elif format == "csv":
        import csv
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "source_ip", "destination_ip",
                "source_port", "destination_port", "protocol",
                "packet_count", "byte_count", "duration",
                "tcp_flags", "direction",
            ])
            writer.writeheader()
            for flow in flows:
                row = {
                    "timestamp": flow.timestamp.isoformat(),
                    "source_ip": flow.source_ip,
                    "destination_ip": flow.destination_ip,
                    "source_port": flow.source_port,
                    "destination_port": flow.destination_port,
                    "protocol": flow.protocol.value,
                    "packet_count": flow.packet_count,
                    "byte_count": flow.byte_count,
                    "duration": flow.duration,
                    "tcp_flags": flow.tcp_flags or "",
                    "direction": flow.direction.value,
                }
                writer.writerow(row)

    return output_path


# ---------------------------------------------------------------------------
# SimulatedReader — a reader that wraps pre-generated flows
# ---------------------------------------------------------------------------

class SimulatedReader:
    """
    A reader adapter for pre-generated flow lists.
    Implements the same interface as BaseReader for pipeline compatibility.
    """

    def __init__(self, flows: list[NormalisedFlow]):
        self._flows = flows
        self._records_read = 0
        self._errors = 0
        self.source_path = None

    def read(self) -> Iterator[NormalisedFlow]:
        for flow in self._flows:
            self._records_read += 1
            yield flow

    def validate_source(self) -> bool:
        return len(self._flows) > 0

    @property
    def records_read(self) -> int:
        return self._records_read

    @property
    def errors(self) -> int:
        return self._errors
