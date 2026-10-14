"""
UniShield — Scan Feature Extractor

Per-source reconnaissance features for port-scan and host-sweep detection.

Only connection attempts count: flows the source initiated. A flow from a
well-known port (< 1024) to a high port is treated as a reply and ignored,
which matters for unidirectional flow exports (sessionized PCAP and Zeek
records already put the initiator in ``source_ip``).

An attempt has failed when it went unanswered or was rejected:
connection state S0/REJ, or RST with no more than 4 packets (handshake
then reset, e.g. a SYN scan of an open port). Without connection state,
a flow with zero responder packets, or a SYN-only TCP flow of at most two
packets, counts as failed.

Per source: unique destination ports and hosts, the most ports probed on
one host (vertical), the most hosts probed on one port (horizontal), the
failure ratio and the largest burst of attempts within ``burst_window_sec``.
The strongest sources are returned in ``scan_candidates`` for the detector;
aggregate features remain for the anomaly model.

SECURITY CONSTRAINTS:
    - Read-only computation over local flow records.
    - No network communication.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import timedelta
from typing import Any, Optional

from unishield.features.base import BaseFeatureExtractor, WindowContext, resolve_window
from unishield.schemas.flow import NormalisedFlow, ProtocolType

_MIN_CANDIDATE_ATTEMPTS = 5
_MAX_CANDIDATES = 10


def is_attempt(flow: NormalisedFlow) -> bool:
    """False for flows that look like a service replying from a well-known port."""
    if flow.source_port is None or flow.destination_port is None:
        return True
    return not (flow.source_port < 1024 <= flow.destination_port)


def is_failed(flow: NormalisedFlow) -> bool:
    """Connection attempt that was unanswered, rejected, or reset before any exchange."""
    if flow.conn_state:
        if flow.conn_state in ("S0", "REJ"):
            return True
        return flow.conn_state == "RST" and flow.packet_count <= 4
    if flow.resp_packets is not None:
        return flow.resp_packets == 0
    flags = (flow.tcp_flags or "").upper()
    return (flow.protocol == ProtocolType.TCP and "SYN" in flags and "ACK" not in flags
            and flow.packet_count <= 2)


@dataclass
class ScanCandidate:
    source_ip: str
    attempts: int
    failed: int
    failed_ratio: float
    unique_ports: int
    unique_hosts: int
    vertical_ports: int
    vertical_host: Optional[str]
    horizontal_hosts: int
    horizontal_port: Optional[int]
    burst: int
    attempts_per_second: float


class ScanFeatureExtractor(BaseFeatureExtractor):
    """Extract scanning-pattern features per source IP."""

    def __init__(self, burst_window_sec: float = 2.0):
        self.burst_window = timedelta(seconds=burst_window_sec)

    @property
    def name(self) -> str:
        return "scan"

    @property
    def feature_names(self) -> list[str]:
        return [
            "unique_dest_ports_per_source",
            "unique_dest_hosts_per_source",
            "connection_rate",
            "failed_connection_ratio",
            "fanout_score",
            "max_vertical_ports",
            "max_horizontal_hosts",
            "burst_connections",
            "scanner_source_ips",
            "top_scanner_ip",
            "top_scanner_port_count",
            "top_scanner_host_count",
            "top_host_scanner_ip",
            "top_host_scanner_horizontal",
            "scan_candidates",
        ]

    def extract(self, flows: list[NormalisedFlow], window: WindowContext | None = None) -> dict[str, Any]:
        empty: dict[str, Any] = {name: 0 for name in self.feature_names}
        empty.update(top_scanner_ip=None, top_host_scanner_ip=None, scan_candidates=[])
        attempts = [f for f in flows if is_attempt(f)]
        if not attempts:
            return empty

        window = resolve_window(flows, window)
        by_source: dict[str, list[NormalisedFlow]] = defaultdict(list)
        for f in attempts:
            by_source[f.source_ip].append(f)

        profiles = [self._profile(src, fs, window.observed_seconds) for src, fs in by_source.items()]
        n = len(profiles)
        total_failed = sum(p.failed for p in profiles)
        avg_ports = sum(p.unique_ports for p in profiles) / n
        fanout = sum((p.unique_ports + p.unique_hosts) / (2 * p.attempts) for p in profiles) / n

        top_port = max(profiles, key=lambda p: (p.unique_ports, p.vertical_ports))
        top_host = max(profiles, key=lambda p: (p.horizontal_hosts, p.unique_hosts))
        candidates = sorted(
            (p for p in profiles if p.attempts >= _MIN_CANDIDATE_ATTEMPTS),
            key=lambda p: max(p.unique_ports, p.horizontal_hosts, p.burst),
            reverse=True,
        )[:_MAX_CANDIDATES]

        return {
            "unique_dest_ports_per_source": round(avg_ports, 2),
            "unique_dest_hosts_per_source": round(sum(p.unique_hosts for p in profiles) / n, 2),
            "connection_rate": round(len(attempts) / window.observed_seconds, 2),
            "failed_connection_ratio": round(total_failed / len(attempts), 4),
            "fanout_score": round(fanout, 4),
            "max_vertical_ports": max(p.vertical_ports for p in profiles),
            "max_horizontal_hosts": max(p.horizontal_hosts for p in profiles),
            "burst_connections": max(p.burst for p in profiles),
            "scanner_source_ips": sum(1 for p in profiles if p.unique_ports > max(avg_ports * 2, 10)),
            "top_scanner_ip": top_port.source_ip,
            "top_scanner_port_count": top_port.unique_ports,
            "top_scanner_host_count": top_port.unique_hosts,
            "top_host_scanner_ip": top_host.source_ip,
            "top_host_scanner_horizontal": top_host.horizontal_hosts,
            "scan_candidates": [asdict(c) for c in candidates],
        }

    def _profile(self, source_ip: str, flows: list[NormalisedFlow], duration: float) -> ScanCandidate:
        host_ports: dict[str, set] = defaultdict(set)
        port_hosts: dict[Optional[int], set] = defaultdict(set)
        ports: set = set()
        for f in flows:
            port_hosts[f.destination_port].add(f.destination_ip)
            if f.destination_port is not None:
                ports.add(f.destination_port)
                host_ports[f.destination_ip].add(f.destination_port)
        failed = sum(1 for f in flows if is_failed(f))
        vertical_host, vertical = max(((h, len(p)) for h, p in host_ports.items()),
                                      key=lambda hp: hp[1], default=(None, 0))
        horizontal_port, horizontal = max(((p, len(h)) for p, h in port_hosts.items()),
                                          key=lambda ph: ph[1], default=(None, 0))
        return ScanCandidate(
            source_ip=source_ip,
            attempts=len(flows),
            failed=failed,
            failed_ratio=round(failed / len(flows), 4),
            unique_ports=len(ports),
            unique_hosts=len({f.destination_ip for f in flows}),
            vertical_ports=vertical,
            vertical_host=vertical_host,
            horizontal_hosts=horizontal,
            horizontal_port=horizontal_port,
            burst=self._burst(flows),
            attempts_per_second=round(len(flows) / duration, 2),
        )

    def _burst(self, flows: list[NormalisedFlow]) -> int:
        """Largest number of attempts that start within burst_window of each other."""
        times = sorted(f.timestamp for f in flows)
        best = start = 0
        for end, t in enumerate(times):
            while t - times[start] > self.burst_window:
                start += 1
            best = max(best, end - start + 1)
        return best
