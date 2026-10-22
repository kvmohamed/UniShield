"""
UniShield — Continuous Synthetic Site Traffic

An endless, seeded, time-ordered stream of SIMULATED flow records for long
runs: soak tests and learning-mode demonstrations. Like the rest of
``unishield.data`` it creates records only; nothing is sent anywhere.

Profiles:
    plain  background traffic (the mix of ``generate_normal_traffic``)
    site   background plus benign behaviours that a real site has and that
           naive rules mistake for attacks (addresses in ``SITE_HOSTS``):
             - a monitoring server polling 20 servers every 30 s
             - two hosts checking one update server every 120 s
             - a vulnerability scanner probing 150 ports on 4 hosts
             - a backup host uploading about 400 MB off-site, 20 files back to back
           ``site_assets()`` is the matching asset inventory.

Attacks: with ``attack_every_sec`` set, a labelled attack episode from
``ATTACK_ROTATION`` starts every that many seconds of traffic time.

Records are emitted in timestamp order, chunk by chunk, so the stream can
feed the pipeline's event-time windows directly.
"""

from __future__ import annotations

import heapq
import itertools
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterator

from unishield.config import AssetInventoryConfig
from unishield.data.sample_generator import (
    LABEL_BENIGN,
    _completed_tcp,
    _flow,
    generate_beacon_traffic,
    generate_ddos_traffic,
    generate_dga_traffic,
    generate_dns_tunnel_traffic,
    generate_exfil_traffic,
    generate_host_sweep_traffic,
    generate_normal_traffic,
    generate_scan_traffic,
)
from unishield.schemas.flow import FlowDirection, NormalisedFlow, ProtocolType

SITE_HOSTS = {
    "monitoring": "10.0.1.10",
    "monitored": [f"10.0.2.{i}" for i in range(201, 221)],
    "update_clients": ["10.0.1.31", "10.0.1.32"],
    "update_server": "203.0.113.80",
    "vulnerability_scanner": "10.0.1.250",
    "scan_targets": ["10.0.2.230", "10.0.2.231", "10.0.2.232", "10.0.2.233"],
    "backup_client": "10.0.2.5",
    "backup_server": "198.51.100.150",
}

_HOUR = 3600.0

Attack = Callable[[random.Random, datetime], list[NormalisedFlow]]

ATTACK_ROTATION: tuple[tuple[str, Attack], ...] = (
    ("port_scan", lambda rng, t: generate_scan_traffic(200, t, rng=rng)),
    ("c2_beacon", lambda rng, t: generate_beacon_traffic(25, t, interval_sec=30, rng=rng)),
    ("exfiltration", lambda rng, t: generate_exfil_traffic(12, t, rng=rng)),
    ("dga", lambda rng, t: generate_dga_traffic(120, t, rng=rng)),
    ("host_sweep", lambda rng, t: generate_host_sweep_traffic(254, t, rng=rng)),
    ("dns_tunnel", lambda rng, t: generate_dns_tunnel_traffic(150, t, rng=rng)),
    ("syn_flood", lambda rng, t: generate_ddos_traffic(3000, t, syn_fraction=1.0, rng=rng)),
)


def site_assets() -> AssetInventoryConfig:
    """Asset inventory describing the ``site`` profile's benign roles."""
    h = SITE_HOSTS
    return AssetInventoryConfig(assets=[
        {"name": "nms", "addresses": [h["monitoring"]], "roles": ["monitoring"]},
        {"name": "patch-mirror", "addresses": [h["update_server"]], "roles": ["update_server"]},
        {"name": "vuln-scanner", "addresses": [h["vulnerability_scanner"]], "roles": ["vulnerability_scanner"]},
        {"name": "offsite-backup", "addresses": [h["backup_server"]], "roles": ["backup_server"]},
    ])


class SiteTraffic:
    """Endless time-ordered synthetic traffic for one site."""

    def __init__(
        self,
        rate_per_sec: float = 100.0,
        start: datetime | None = None,
        *,
        seed: int = 7,
        profile: str = "site",
        attack_every_sec: float | None = None,
        scan_every_sec: float = 6 * _HOUR,
        backup_every_sec: float = 6 * _HOUR,
    ):
        if profile not in ("plain", "site"):
            raise ValueError("profile must be 'plain' or 'site'")
        if rate_per_sec <= 0:
            raise ValueError("rate_per_sec must be positive")
        self.rate = rate_per_sec
        self.profile = profile
        self.rng = random.Random(seed)
        self.start = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.now = self.start
        self.records = 0
        self.injected: Counter[str] = Counter()
        self._pending: list[tuple[datetime, int, NormalisedFlow]] = []
        self._seq = itertools.count()
        self._attacks = itertools.cycle(ATTACK_ROTATION)
        self._events: dict[str, tuple[datetime, float]] = {}
        if profile == "site":
            self._events.update(
                poll=(self.start, 30.0),
                update=(self.start + timedelta(seconds=7), 120.0),
                scan=(self.start + timedelta(minutes=30), scan_every_sec),
                backup=(self.start + timedelta(minutes=60), backup_every_sec),
            )
        if attack_every_sec:
            self._events["attack"] = (self.start + timedelta(seconds=attack_every_sec), attack_every_sec)

    # ------------------------------------------------------------- stream

    def stream(self, chunk_sec: float = 1.0) -> Iterator[NormalisedFlow]:
        while True:
            yield from self.next_chunk(chunk_sec)

    def next_chunk(self, seconds: float = 1.0) -> list[NormalisedFlow]:
        """About ``seconds`` of traffic after the previous chunk, in timestamp order."""
        count = max(1, int(self.rate * seconds + self.rng.random()))
        mean_gap_ms = 1000.0 * seconds / count
        gap = (max(0, int(mean_gap_ms * 0.5)), max(1, int(round(mean_gap_ms * 1.5))))
        flows = generate_normal_traffic(count, self.now, gap_ms=gap, rng=self.rng)
        end = max(flows[-1].timestamp, self.now + timedelta(milliseconds=1))
        self._schedule(end)
        while self._pending and self._pending[0][0] < end:
            flows.append(heapq.heappop(self._pending)[2])
        flows.sort(key=lambda f: f.timestamp)
        self.now = end
        self.records += len(flows)
        return flows

    # ------------------------------------------------------------- events

    def _push(self, flows: list[NormalisedFlow]) -> None:
        for f in flows:
            heapq.heappush(self._pending, (f.timestamp, next(self._seq), f))

    def _schedule(self, until: datetime) -> None:
        for name, (due, every) in list(self._events.items()):
            while due < until:
                self._push(getattr(self, f"_{name}")(due))
                due += timedelta(seconds=every)
            self._events[name] = (due, every)

    def _poll(self, t: datetime) -> list[NormalisedFlow]:
        h = SITE_HOSTS
        return [_completed_tcp(self.rng, t + timedelta(seconds=1.5 * i), h["monitoring"], target, 443,
                               FlowDirection.INTERNAL, up=(200, 400), down=(400, 2000))
                for i, target in enumerate(h["monitored"])]

    def _update(self, t: datetime) -> list[NormalisedFlow]:
        h = SITE_HOSTS
        return [_completed_tcp(self.rng, t + timedelta(seconds=3 * i), client, h["update_server"], 443,
                               FlowDirection.OUTBOUND, up=(300, 600), down=(800, 3000))
                for i, client in enumerate(h["update_clients"])]

    def _scan(self, t: datetime) -> list[NormalisedFlow]:
        h, rng = SITE_HOSTS, self.rng
        flows, ports = [], rng.sample(range(1, 10_000), 150)
        for k, (host, port) in enumerate(itertools.product(h["scan_targets"], ports)):
            closed = rng.random() < 0.9
            flows.append(_flow(
                timestamp=t + timedelta(milliseconds=50 * k), src=h["vulnerability_scanner"], dst=host,
                sport=rng.randint(40000, 60000), dport=port, protocol=ProtocolType.TCP,
                orig_packets=1 if closed else 3, resp_packets=1 if closed else 2,
                orig_bytes=44 if closed else 180, resp_bytes=40 if closed else 120,
                duration=0.001 if closed else 0.02, conn_state="REJ" if closed else "SF",
                direction=FlowDirection.INTERNAL, label=LABEL_BENIGN,
                tcp_flags="SYN" if closed else "ACK,FIN,PSH,SYN",
            ))
        return flows

    def _backup(self, t: datetime) -> list[NormalisedFlow]:
        """20 files of about 20 MB, one connection each, sent back to back."""
        h, rng = SITE_HOSTS, self.rng
        flows = []
        for _ in range(20):
            size = rng.randint(5_000_000, 35_000_000)
            duration = size / rng.uniform(0.8e6, 1.6e6)
            flows.append(_flow(
                timestamp=t, src=h["backup_client"], dst=h["backup_server"],
                sport=rng.randint(49152, 65535), dport=22, protocol=ProtocolType.TCP,
                orig_packets=size // 1400, resp_packets=size // 5600, orig_bytes=size, resp_bytes=200_000,
                duration=round(duration, 3), conn_state="SF", direction=FlowDirection.OUTBOUND,
                label=LABEL_BENIGN, tcp_flags="ACK,FIN,PSH,SYN",
            ))
            t += timedelta(seconds=duration + rng.uniform(0.2, 3.0))
        return flows

    def _attack(self, t: datetime) -> list[NormalisedFlow]:
        name, build = next(self._attacks)
        self.injected[name] += 1
        return build(self.rng, t)
