"""
UniShield — Controlled Test Traffic Generator

Generates reproducible, ground-truth-labelled test scenarios
for real-time verification. Each scenario records its expected
threat labels, timestamps, and record counts.

SAFETY:
    - All traffic is synthetic NormalisedFlow objects.
    - No packets are sent on any network interface.
    - No external systems are contacted.
    - All IPs are RFC 5737 / RFC 2544 documentation ranges.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

from unishield.schemas.flow import (
    FlowDirection,
    InputSource,
    NormalisedFlow,
    ProtocolType,
)


@dataclass
class ScenarioMetadata:
    """Ground-truth metadata for a test scenario."""
    scenario_name: str
    scenario_id: str
    seed: int
    start_timestamp: str
    end_timestamp: str
    total_records: int
    expected_threat_labels: list[str]
    benign_records: int
    threat_records: int
    description: str
    generated_at: str


def _set_seed(seed: int) -> None:
    random.seed(seed)


def generate_benign_scenario(
    count: int = 500,
    seed: int = 42,
    start_time: datetime | None = None,
) -> tuple[list[NormalisedFlow], ScenarioMetadata]:
    """Generate pure benign traffic with no attack patterns."""
    _set_seed(seed)
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    flows = []
    t = start_time

    for i in range(count):
        t += timedelta(milliseconds=random.randint(200, 3000))
        proto = random.choices(
            [ProtocolType.TCP, ProtocolType.UDP, ProtocolType.ICMP],
            weights=[0.7, 0.25, 0.05],
        )[0]

        flow = NormalisedFlow(
            event_id=f"benign-{seed}-{i:06d}",
            timestamp=t,
            source_ip=f"10.0.{random.randint(1,5)}.{random.randint(1,254)}",
            destination_ip=random.choice([
                "93.184.216.34", "172.217.14.206", "151.101.1.140",
                "104.16.132.229", "13.107.42.14",
            ]),
            source_port=random.randint(1024, 65535) if proto != ProtocolType.ICMP else None,
            destination_port=random.choice([80, 443, 53, 22, 8080]) if proto != ProtocolType.ICMP else None,
            protocol=proto,
            packet_count=random.randint(1, 40),
            byte_count=random.randint(64, 12000),
            duration=round(random.uniform(0.01, 20.0), 3),
            tcp_flags="SYN,ACK" if proto == ProtocolType.TCP else None,
            direction=random.choice([FlowDirection.OUTBOUND, FlowDirection.INBOUND]),
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    meta = ScenarioMetadata(
        scenario_name="benign_baseline",
        scenario_id=f"benign-{seed}",
        seed=seed,
        start_timestamp=flows[0].timestamp.isoformat(),
        end_timestamp=flows[-1].timestamp.isoformat(),
        total_records=count,
        expected_threat_labels=[],
        benign_records=count,
        threat_records=0,
        description="Pure benign traffic — no attacks. Expect zero high-severity alerts.",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return flows, meta


def generate_ddos_scenario(
    count: int = 2000,
    seed: int = 100,
    start_time: datetime | None = None,
) -> tuple[list[NormalisedFlow], ScenarioMetadata]:
    """Generate DDoS flood scenario with benign background."""
    _set_seed(seed)
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    flows = []
    t = start_time
    target_ip = "10.0.1.100"
    benign_count = count // 4
    ddos_count = count - benign_count

    # Benign background
    for i in range(benign_count):
        t += timedelta(milliseconds=random.randint(100, 1000))
        flow = NormalisedFlow(
            event_id=f"ddos-bg-{seed}-{i:06d}",
            timestamp=t,
            source_ip=f"10.0.2.{random.randint(1,254)}",
            destination_ip=random.choice(["93.184.216.34", "172.217.14.206"]),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443]),
            protocol=ProtocolType.TCP,
            packet_count=random.randint(1, 20),
            byte_count=random.randint(64, 5000),
            duration=round(random.uniform(0.01, 5.0), 3),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    # DDoS traffic — high rate SYN flood with large packet counts
    ddos_start = t
    for i in range(ddos_count):
        t += timedelta(milliseconds=random.randint(1, 5))
        flow = NormalisedFlow(
            event_id=f"ddos-atk-{seed}-{i:06d}",
            timestamp=t,
            source_ip=f"198.18.{random.randint(0,255)}.{random.randint(1,254)}",
            destination_ip=target_ip,
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443, 8080]),
            protocol=ProtocolType.TCP,
            packet_count=random.randint(50, 200),
            byte_count=random.randint(3000, 12000),
            duration=0.0,
            tcp_flags="SYN",
            direction=FlowDirection.INBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    flows.sort(key=lambda f: f.timestamp)

    meta = ScenarioMetadata(
        scenario_name="ddos_syn_flood",
        scenario_id=f"ddos-{seed}",
        seed=seed,
        start_timestamp=flows[0].timestamp.isoformat(),
        end_timestamp=flows[-1].timestamp.isoformat(),
        total_records=len(flows),
        expected_threat_labels=["DDOS_VOLUMETRIC", "SYN_FLOOD"],
        benign_records=benign_count,
        threat_records=ddos_count,
        description="SYN flood DDoS attack against 10.0.1.100 with benign background.",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return flows, meta


def generate_scan_scenario(
    count: int = 400,
    seed: int = 200,
    start_time: datetime | None = None,
) -> tuple[list[NormalisedFlow], ScenarioMetadata]:
    """Generate port scanning scenario."""
    _set_seed(seed)
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    flows = []
    t = start_time
    scanner_ip = "198.18.0.100"
    target_ip = "10.0.1.50"
    benign_count = count // 3
    scan_count = count - benign_count

    # Benign background
    for i in range(benign_count):
        t += timedelta(milliseconds=random.randint(200, 2000))
        flow = NormalisedFlow(
            event_id=f"scan-bg-{seed}-{i:06d}",
            timestamp=t,
            source_ip=f"10.0.2.{random.randint(1,50)}",
            destination_ip="93.184.216.34",
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443]),
            protocol=ProtocolType.TCP,
            packet_count=random.randint(1, 20),
            byte_count=random.randint(64, 5000),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    # Port scan
    ports = random.sample(range(1, 65536), min(scan_count, 5000))
    for i in range(scan_count):
        t += timedelta(milliseconds=random.randint(10, 150))
        flow = NormalisedFlow(
            event_id=f"scan-atk-{seed}-{i:06d}",
            timestamp=t,
            source_ip=scanner_ip,
            destination_ip=target_ip if random.random() < 0.7 else f"10.0.1.{random.randint(1,254)}",
            source_port=random.randint(1024, 65535),
            destination_port=ports[i % len(ports)],
            protocol=ProtocolType.TCP,
            packet_count=random.randint(1, 2),
            byte_count=random.randint(40, 100),
            duration=round(random.uniform(0.001, 0.3), 3),
            tcp_flags="SYN",
            direction=FlowDirection.INBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    flows.sort(key=lambda f: f.timestamp)

    meta = ScenarioMetadata(
        scenario_name="port_scan",
        scenario_id=f"scan-{seed}",
        seed=seed,
        start_timestamp=flows[0].timestamp.isoformat(),
        end_timestamp=flows[-1].timestamp.isoformat(),
        total_records=len(flows),
        expected_threat_labels=["PORT_SCAN", "HOST_SCAN"],
        benign_records=benign_count,
        threat_records=scan_count,
        description=f"Port scan from {scanner_ip} targeting {target_ip} with benign background.",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return flows, meta


def generate_beacon_scenario(
    count: int = 300,
    seed: int = 300,
    start_time: datetime | None = None,
) -> tuple[list[NormalisedFlow], ScenarioMetadata]:
    """Generate C2 beaconing scenario with regular intervals."""
    _set_seed(seed)
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    flows = []
    t = start_time
    beacon_ip = "10.0.1.50"
    c2_server = "198.51.100.42"
    beacon_count = 80
    benign_count = count - beacon_count
    interval_sec = 2.0  # 2-second beacon interval for denser evidence
    jitter_pct = 3.0

    # Benign background
    for i in range(benign_count):
        t_bg = start_time + timedelta(seconds=random.uniform(0, beacon_count * interval_sec))
        flow = NormalisedFlow(
            event_id=f"beacon-bg-{seed}-{i:06d}",
            timestamp=t_bg,
            source_ip=f"10.0.2.{random.randint(1,50)}",
            destination_ip=random.choice(["93.184.216.34", "172.217.14.206"]),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443]),
            protocol=ProtocolType.TCP,
            packet_count=random.randint(1, 30),
            byte_count=random.randint(64, 10000),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    # Beaconing traffic — regular intervals
    t_beacon = start_time
    for i in range(beacon_count):
        jitter = interval_sec * jitter_pct / 100.0
        actual_interval = interval_sec + random.uniform(-jitter, jitter)
        t_beacon += timedelta(seconds=max(1.0, actual_interval))
        flow = NormalisedFlow(
            event_id=f"beacon-atk-{seed}-{i:06d}",
            timestamp=t_beacon,
            source_ip=beacon_ip,
            destination_ip=c2_server,
            source_port=random.randint(49152, 65535),
            destination_port=443,
            protocol=ProtocolType.TCP,
            packet_count=random.randint(3, 7),
            byte_count=random.randint(250, 450),
            duration=round(random.uniform(0.1, 1.5), 3),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            tls_version="TLSv1.2",
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    flows.sort(key=lambda f: f.timestamp)

    meta = ScenarioMetadata(
        scenario_name="c2_beaconing",
        scenario_id=f"beacon-{seed}",
        seed=seed,
        start_timestamp=flows[0].timestamp.isoformat(),
        end_timestamp=flows[-1].timestamp.isoformat(),
        total_records=len(flows),
        expected_threat_labels=["C2_BEACONING"],
        benign_records=benign_count,
        threat_records=beacon_count,
        description=f"C2 beaconing from {beacon_ip} to {c2_server} at ~{interval_sec}s intervals.",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return flows, meta


def generate_exfil_scenario(
    count: int = 400,
    seed: int = 400,
    start_time: datetime | None = None,
) -> tuple[list[NormalisedFlow], ScenarioMetadata]:
    """Generate data exfiltration scenario with large outbound transfers."""
    _set_seed(seed)
    if start_time is None:
        start_time = datetime.now(timezone.utc)

    flows = []
    t = start_time
    exfil_src = "10.0.2.200"
    exfil_dst = "203.0.113.99"
    benign_count = count // 3
    exfil_count = count - benign_count

    # Benign background
    for i in range(benign_count):
        t += timedelta(milliseconds=random.randint(200, 2000))
        flow = NormalisedFlow(
            event_id=f"exfil-bg-{seed}-{i:06d}",
            timestamp=t,
            source_ip=f"10.0.1.{random.randint(1,50)}",
            destination_ip=random.choice(["93.184.216.34", "172.217.14.206"]),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443]),
            protocol=ProtocolType.TCP,
            packet_count=random.randint(1, 20),
            byte_count=random.randint(64, 5000),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    # Exfiltration — large outbound transfers
    for i in range(exfil_count):
        t += timedelta(seconds=random.uniform(1, 8))
        flow = NormalisedFlow(
            event_id=f"exfil-atk-{seed}-{i:06d}",
            timestamp=t,
            source_ip=exfil_src,
            destination_ip=exfil_dst,
            source_port=random.randint(49152, 65535),
            destination_port=random.choice([443, 8443, 4444]),
            protocol=ProtocolType.TCP,
            packet_count=random.randint(50, 500),
            byte_count=random.randint(500_000, 5_000_000),
            duration=round(random.uniform(5.0, 60.0), 3),
            tcp_flags="SYN,ACK",
            direction=FlowDirection.OUTBOUND,
            source=InputSource.SIMULATED,
        )
        flows.append(flow)

    flows.sort(key=lambda f: f.timestamp)

    meta = ScenarioMetadata(
        scenario_name="data_exfiltration",
        scenario_id=f"exfil-{seed}",
        seed=seed,
        start_timestamp=flows[0].timestamp.isoformat(),
        end_timestamp=flows[-1].timestamp.isoformat(),
        total_records=len(flows),
        expected_threat_labels=["DATA_EXFILTRATION"],
        benign_records=benign_count,
        threat_records=exfil_count,
        description=f"Data exfiltration from {exfil_src} to {exfil_dst} with large outbound.",
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    return flows, meta


SCENARIO_GENERATORS = {
    "benign": generate_benign_scenario,
    "ddos": generate_ddos_scenario,
    "scan": generate_scan_scenario,
    "beacon": generate_beacon_scenario,
    "exfil": generate_exfil_scenario,
}


def save_scenario(
    flows: list[NormalisedFlow],
    meta: ScenarioMetadata,
    output_dir: Path,
) -> Path:
    """Save scenario flows and metadata to disk."""
    scenario_dir = output_dir / meta.scenario_id
    scenario_dir.mkdir(parents=True, exist_ok=True)

    # Save flows as JSONL
    flows_path = scenario_dir / "flows.jsonl"
    with open(flows_path, "w", encoding="utf-8") as f:
        for flow in flows:
            f.write(flow.model_dump_json() + "\n")

    # Save metadata
    meta_path = scenario_dir / "metadata.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(asdict(meta), f, indent=2)

    return scenario_dir


def generate_all_scenarios(
    output_dir: Path,
    runs_per_scenario: int = 5,
) -> list[ScenarioMetadata]:
    """Generate all scenarios with multiple seeds for reproducibility."""
    all_meta = []
    output_dir.mkdir(parents=True, exist_ok=True)

    for scenario_name, generator in SCENARIO_GENERATORS.items():
        for run_idx in range(runs_per_scenario):
            seed = hash(f"{scenario_name}-{run_idx}") % (2**31)
            flows, meta = generator(seed=seed)
            save_scenario(flows, meta, output_dir)
            all_meta.append(meta)
            print(f"  Generated: {meta.scenario_id} ({meta.total_records} records)")

    return all_meta


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

    output = Path(__file__).resolve().parent.parent / "data" / "test_scenarios"
    print(f"Generating test scenarios in {output}")
    metas = generate_all_scenarios(output)
    print(f"\nGenerated {len(metas)} scenarios")
